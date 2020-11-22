const NodeRSA = require("node-rsa");
const fs = require("fs");

const key = new NodeRSA();

// key.generateKeyPair();

// const privateKey = key.exportKey("pkcs1-private-pem");
// const publicKey = key.exportKey("pkcs1-public-pem");

// fs.writeFileSync("privateKey.txt", privateKey);
// fs.writeFileSync("publicKey.txt", publicKey);

const privateKey = fs.readFileSync("privateKey.txt");
const publicKey = fs.readFileSync("publicKey.txt");

key.importKey(privateKey, "pkcs1-private-pem");
key.importKey(publicKey, "pkcs1-public-pem");

// const data = fs.readFileSync('./bufferdata');
data = "some data"
console.log(data);

const encData = key.encryptPrivate(Buffer.from(data), "base64");
console.log(encData);
fs.writeFileSync("encrypteddata", encData, { encoding: "base64" });

const encData1 = fs.readFileSync("./encrypteddata", { encoding: "base64" });
const decData = key.decryptPublic(encData1);
console.log(decData.toString());
fs.writeFileSync("decrypteddata", decData);
