// require "base64"

function AladdinEtokenModel(usb_id) {
  this.usb_id = usb_id;

  var info = AladdinEtoken.plugin().getTokenInfo(this.usb_id);
  this.uid = info[0];
}

with(AladdinEtokenModel) {
	prototype.containers = function() {
    var certs = AladdinEtoken.plugin().getCertificateList(this.usb_id);
    var container_models = [];
    $.each(certs, function(i, cert) {
      container_models.push(new ContainerModel(cert[0], cert[1]));
    });
    return container_models;
	}

  prototype.bind = function(options) {
    try {
      AladdinEtoken.plugin().bindToken(this.usb_id, options.pin);
      options.success();
    } catch(error) {
      options.error();
    }
  }

  prototype.unbind = function() {
    AladdinEtoken.plugin().unbindToken();
  }

  prototype.binded = function() {
    var state_array = AladdinEtoken.plugin().getLoggedInState();
    var state_id = state_array[0];
    var state_connection_id = state_array[1];
    var state_usb_id = state_array[2];

    return (state_usb_id == this.usb_id) && (state_id > 0);
  }
}

function ContainerModel(id, description) {
	this.id = id;
	this.description = description;
}

with(ContainerModel) {
  prototype.sign = function(content) {
    var content_encoded = AladdinEtoken.utf8_encode_to_bytes_array(content);
		var signature_bytes_array = AladdinEtoken.plugin().signData(this.id, content_encoded, false);
		var signature_base64 = AladdinEtoken._bytes_array_to_base64(signature_bytes_array);
		return signature_base64;
	}

	prototype.set_certificate = function(certificate_base64) {
	  certificate_base64 = AladdinEtoken._clean_base64(certificate_base64);
		var certificate_string = $.base64.decode(certificate_base64);
		var certificate_bytes_array = AladdinEtoken.utf8_encode_to_bytes_array(certificate_string);
		AladdinEtoken.plugin().writeCertificate(this.id, certificate_bytes_array);
		return true;
	}

	prototype.certificate = function() {
		var bytes_array = AladdinEtoken.plugin().readCertificate(this.id);
		var base64 = AladdinEtoken._bytes_array_to_base64(bytes_array);
		var base64_parts = base64.match(/.{1,64}/g);

		var standard = "-----BEGIN CERTIFICATE-----\n";
		$.each(base64_parts, function(index, part) {
			standard += part+"\n";
		});
		standard += "-----END CERTIFICATE-----";

		return standard;
	}
}

var AladdinEtoken = {
  plugin_installed: function() {
    return (typeof (AladdinEtoken.plugin().valid) != 'undefined' && AladdinEtoken.plugin().valid != null);
  },

  present: function() {
    return AladdinEtoken.plugin_installed() ? AladdinEtoken.plugin().getAllTokens().length : false;
  },

  blank: function() {
    return !AladdinEtoken.present();
  },

  state_change: function(func) {
    AladdinEtoken.subscribe('loginstatechanged', function (state) {
      func(state);
    });
  },

  inserted: function(func) {
    AladdinEtoken.subscribe('tokenadded', function (usb_id) {
      var etoken = new AladdinEtokenModel(usb_id);
      func(etoken);
    });
  },

  removed: function(func) {
    AladdinEtoken.subscribe('tokenremoved', function (usb_id) {
      func(usb_id);
    });
  },

	all: function() {
		var token_usb_ids = AladdinEtoken.plugin().getAllTokens();
		var tokens = [];
		$.each(token_usb_ids, function(i, token_usb_id) {
		  tokens.push(new AladdinEtokenModel(token_usb_id));
		});
		return tokens;
	},

  first: function() {
    var etokens = AladdinEtoken.all();
    return etokens.length ? etokens[0] : null;
  },

  find_by_uid: function(uid) {
    var result;
    $.each(AladdinEtoken.all(), function(i, etoken) {
      if (etoken.uid == uid) {
        result = etoken;
      }
    });
    return result;
  },

  // Options:
  // containerName (*) - Имя контейнера
  // dn (*) - хеш с частями DN (например, {"CN": "Alexander Ivanov", "L": "Москва", "C": "RU"})
  // extendedKeyUsage - расширенное использование ключа. OID через запятую (например: "1.3.6.1.5.5.7.3.2,1.3.6.1.5.5.7.3.4,1.2.643.6.3.1.2.1")
  // certificatePolicies  - политики применения сертификата. OID через запятую (например: "1.2.643.3.8.100.1,1.2.643.3.8.100.1.2")
	create_csr: function(options) {
    var container_id = AladdinEtoken.plugin().createContainer("A", options.containerName);

    var aladdin_format_dn = [];
    for (var key in options.dn) {
      aladdin_format_dn.push(key);
      aladdin_format_dn.push(options.dn[key]);
    }

    var extensions = ["keyUsage", "digitalSignature"];
    if (options.extendedKeyUsage) {
      extensions.push("extendedKeyUsage");
      extensions.push(options.extendedKeyUsage);
    }
    if (options.certificatePolicies) {
      extensions.push("certificatePolicies");
      extensions.push(options.certificatePolicies);
    }

    var csr = AladdinEtoken.plugin().genCSR(container_id, aladdin_format_dn, extensions);
    var csr_encoded = AladdinEtoken._bytes_array_to_base64(csr);

    return csr_encoded;
	},

  // private

	plugin: function() {
    if (!document.getElementById('etgPlugin')) {
      $("body").append('<object id="etgPlugin" type="application/x-etokengost" width="0" height="0">');
    }
    return document.getElementById('etgPlugin');
	},

  subscribe: function(name, func) {
    if (window.addEventListener) {
      AladdinEtoken.plugin().addEventListener(name, func, false);
    }
    else {
      AladdinEtoken.plugin().attachEvent("on" + name, func);
    }
  },

  utf8_encode_to_bytes_array: function(string) {
    var byte_array = [];
    for(var i = 0; i < string.length; i++) {
      byte_array.push(string.charCodeAt(i));
    }

    return byte_array;
  },

  _bytes_array_to_base64: function(byte_array) {
    var plain_string = "";
    for(var i = 0; i < byte_array.length; i++) {
      plain_string += String.fromCharCode(byte_array[i]);
    }
    var encoded_string = $.base64.encode(plain_string);
    return encoded_string;
  },

  _clean_base64: function(base64) {
    return base64.replace(/[\r\n\s]/g, '');
  }

};
