const path = require("path");
const crypto = require("crypto");
const zlib = require("zlib");
const fs = require("fs");

const express = require("express");
const upload = require("express-fileupload");
const splitFile = require("split-file");
const admin = require("firebase-admin");

const AppendInitVect = require("./appendInitVector");

const app = express();

app.use(express.static(path.join(__dirname, "public")));

app.use(
	upload({
		createParentPath: true,
	})
);

// // Firebase Admin initialize
// var serviceAccount = require("./encrypted-storage-system-firebase-adminsdk-xqaq0-a5caa56742.json");
// admin.initializeApp({
// 	credential: admin.credential.cert(serviceAccount),
// 	databaseURL: "https://encrypted-storage-system.firebaseio.com",
// });

// const defaultApp = admin.initializeApp(defaultAppConfig);


// Global Variables
const chunkSize = 1024 * 1024;
let keyArray = new Array();
let namesArray = new Array();
let encKeyArray = new Array();

const uploadFile = (file) => {
	return new Promise((resolve, reject) => {
		file.mv(path.join(__dirname, "uploads", file.name), (err) => {
			if (err) reject(err);
			resolve("done");
		});
	});
};

function generateKey(filePath, index) {
	const KEY = crypto.createHash("sha256").update(filePath).digest();
	let keyItem = new Object();
	keyItem.index = index;
	keyItem.key = KEY;
	keyArray.push(keyItem);
}

function encryptFile(filePath, index) {
	const initVector = crypto.randomBytes(16);
	const key = keyArray[index].key;
	let encFilePath = filePath + ".enc";
	const readStream = fs.createReadStream(filePath);
	const gzip = zlib.createGzip();
	const writeStream = fs.createWriteStream(encFilePath);

	const cipher = crypto.createCipheriv("aes256", key, initVector);
	const appendInitVect = new AppendInitVect(initVector);

	readStream.pipe(gzip).pipe(cipher).pipe(appendInitVect).pipe(writeStream);
	namesArray.push(encFilePath);
}

function decryptFile(encFilePath, index) {
	const readIV = fs.createReadStream(encFilePath, { end: 15 });
	let initVector;
	readIV.on("data", (chunk) => {
		initVector = chunk;
	});
	readIV.on("close", () => {
		const readStream = fs.createReadStream(encFilePath, { start: 16 });
		const unzip = zlib.createGunzip();
		const key = keyArray[index].key;
		const decipher = crypto.createDecipheriv("aes256", key, initVector);

		fs.unlinkSync(encFilePath.replace(".enc", ""));

		const writeStream = fs.createWriteStream(encFilePath.replace(".enc", ""));
		readStream.pipe(decipher).pipe(unzip).pipe(writeStream);
	});
}

app.post("/upload", async (req, res) => {
	try {
		if (!req.files) {
			res.status(400);
			res.send("File not uploaded");
		} else {
			uploadFile(req.files.upload)
				.then(() => {
					splitFile
						.splitFileBySize(path.join(__dirname, "uploads", req.files.upload.name), chunkSize)
						.then((names) => {
							names.forEach((fileLocation, index) => {
								generateKey(fileLocation, index);
								encryptFile(fileLocation, index);
							});
							keyArray.forEach((keyObject, index) => {
								const encryptedKey = crypto.privateEncrypt(
									{
										key: req.body.privateKey,
										padding: crypto.constants.RSA_PKCS1_OAEP_PADDING,
										oaepHash: "sha256",
									},
									Buffer.from(keyObject.key)
								);
								encKeyArray.push(encryptedKey.toString("base64"));
							});
							 
							res.status(200);
							res.send("Uploaded Files Sucessfully");
						})
						.catch((err) => {
							console.log(err);
							res.status(500);
							res.send("Error splitting file");
							res.end();
						});
				})
				.catch((err) => {
					console.log(err);
					res.status(500);
					res.send("Error saving file");
					res.end();
				});
		}
	} catch (err) {
		res.status(500).send(err);
	}
});

const PORT = process.env.PORT || 5000;
app.listen(PORT, () => {
	console.log(`Server started on PORT ${PORT}`);
});
