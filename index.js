const path = require("path");
const crypto = require("crypto");
const zlib = require("zlib");
const fs = require("fs");

const express = require("express");
const upload = require("express-fileupload");
const splitFile = require("split-file");
const NodeRSA = require("node-rsa");

const AppendInitVect = require("./appendInitVector");
const { SSL_OP_ALL } = require("constants");
const { stderr } = require("process");

const app = express();

app.use(express.static(path.join(__dirname, "public")));
app.use(express.urlencoded({ extended: false }));
app.use(express.json());
app.use(
	upload({
		createParentPath: true,
	})
);

// Global Variables
const chunkSize = 1024 * 1024;
let keyArray = new Array();
let namesArray = new Array();
let encKeyArray = new Array();
let decKeyArray = new Array();
let decNamesArray = new Array();
let origFile;

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

function decryptFile(encFilePath, decFilePath, index) {
	const readIV = fs.createReadStream(encFilePath, { end: 15 });
	let initVector;
	readIV.on("data", (chunk) => {
		initVector = chunk;
	});
	readIV.on("close", () => {
		const readStream = fs.createReadStream(encFilePath, { start: 16 });
		const unzip = zlib.createGunzip();
		const key = decKeyArray[index];
		const decipher = crypto.createDecipheriv("aes256", key, initVector);
		const writeStream = fs.createWriteStream(decFilePath);
		readStream.pipe(decipher).pipe(unzip).pipe(writeStream);
		decNamesArray.push(decFilePath);
	});
}

app.post("/upload", async (req, res) => {
	try {
		if (!req.files) {
			res.status(400);
			res.send("File not uploaded");
		} else {
			origFile = req.files.upload.name;
			uploadFile(req.files.upload)
				.then(() => {
					splitFile
						.splitFileBySize(path.join(__dirname, "uploads", req.files.upload.name), chunkSize)
						.then((names) => {
							names.forEach((fileLocation, index) => {
								generateKey(fileLocation, index);
								encryptFile(fileLocation, index);
							});

							const rsa_key = new NodeRSA();
							const privateKey = fs.readFileSync("privateKey.txt");
							rsa_key.importKey(privateKey, "pkcs1-private-pem");
							keyArray.forEach((keyObject, index) => {
								let encData = rsa_key.encryptPrivate(Buffer.from(keyObject.key), "base64");
								encKeyArray.push(encData);
							});
							fs.writeFileSync("1", encKeyArray[0], { encoding: "base64" });
							// let numOfParts = encKeyArray.length.toString() + "\n";
							// fs.appendFileSync("1", numOfParts);
							// encKeyArray.forEach((encKey, index) => {
							// 	fs.appendFileSync("1", encKey.toString(), { encoding: "base64" });
							// 	fs.appendFileSync("1", "\n");
							// });
							// namesArray.forEach((filePath, index) => {
							// 	fs.appendFileSync("1", filePath + "\n");
							// });
							res.status(200);
							res.send('Uploaded Files Sucessfully. The File ID is: "1"');
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

app.post("/download", (req, res) => {
	const publicKey = fs.readFileSync("publicKey.txt");
	const dec_rsa_key = new NodeRSA();
	dec_rsa_key.importKey(publicKey, "pkcs1-public-pem");
	const fileId = req.body.fileId.toString();
	const encryptedKey0 = fs.readFileSync(fileId, { encoding: "base64" });
	const decryptedKey0 = dec_rsa_key.decryptPublic(encryptedKey0);
	// decKeyArray.push(decryptedKey0);
	// let decryptedFileName = namesArray[0].split("/").pop().replace(".enc", "");
	// let decryptedFilePath = path.join(__dirname, "downloads", decryptedFileName);
	// decryptFile(namesArray[0], decryptedFilePath, 0);
	// let decData = dec_rsa_key.decryptPublic(encKeyArray[i]);
	decKeyArray.push(decryptedKey0);
	let decryptedFileName = namesArray[0].split("/").pop().replace(".enc", "");
	let decryptedFilePath = path.join(__dirname, "downloads", decryptedFileName);

	decryptFile(namesArray[0], decryptedFilePath, 0);

	for (let i = 1; i < encKeyArray.length; i++) {
		let decData = dec_rsa_key.decryptPublic(encKeyArray[i]);
		decKeyArray.push(decData);
		let decryptedFileName = namesArray[i].split("/").pop().replace(".enc", "");
		let decryptedFilePath = path.join(__dirname, "downloads", decryptedFileName);

		decryptFile(namesArray[i], decryptedFilePath, i);
	}
	let decryptedOutputFile = path.join(__dirname, "downloads", origFile);
	setTimeout(() => {
		splitFile
			.mergeFiles(decNamesArray, decryptedOutputFile)
			.then(() => {
				res.status(200).send("Successfully decrypted file");
			})
			.catch((err) => {
				console.log(err);
				res.status(500).send("Error decrypting file");
			});
	}, 2000);
});

const PORT = process.env.PORT || 5000;
app.listen(PORT, () => {
	console.log(`Server started on PORT ${PORT}`);
});
