module.exports = function (RED) {
	var Crypto = require("crypto");

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
						//var signingKey = "FeoQddXfIp6ZQ6Stb1pa8u/Gmez0z97sn/izVm0WBoY=";
						var rawSigningKey = new Buffer.from(node.key, "base64");
						//var body = '{"network_id":6931881,"event":"network.created","timestamp":"2022-10-04T18:33:37.035Z"}';
						var utf8EncodedBody = Buffer.from(msg.payload, "utf8");
						var signature = Crypto.createHmac("sha256", rawSigningKey).update(utf8EncodedBody).digest("base64");
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
