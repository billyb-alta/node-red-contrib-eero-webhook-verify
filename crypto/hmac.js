module.exports = function (RED) {
	var hmacSHA256 = require("crypto-js/hmac-sha256");
	var Base64 = require('crypto-js/enc-base64');

	function DigestNode(config) {
		RED.nodes.createNode(this, config);

		var node = this;
		node.key = config.key;

		node.on('input', function (msg) {
			// first check if secret key was sent via msg first. If true overwrite user entered secret key in configuration.
			if(msg.secretkey) {
				node.key = msg.secretkey;
			}
			// check configurations
			if(!node.algorithm || !node.key) {
				// rising misconfiguration error
				node.error("Missing configuration, please check your algorithm or key.", msg);
			} else {
				if (!msg.req.headers.Eero-Signature){
					node.error("Eero-Signature missing from message", msg);
				}else{
					// check the payload
					if(msg.payload) {
						// debugging message
						node.debug('Creating a digest of payload using '+node.algorithm);
						// digest with Crypto
						var signature = Base64.stringify(hmacSHA256(msg.payload, Base64.parse(node.key)));
						if (signature == msg.req.headers.Eero-Signature){
							result = true;
						}else{
							result = false;
						msg.payload = result;
					} else {
						// debugging message
						node.trace('Nothing to digest: empty payload');
					}
				}

				node.send(msg);
			}
		});
	}

	RED.nodes.registerType("hmac", DigestNode);
};
