// Adaptation of https://github.com/sh-dv/hat.sh/
// LimitedEncryptionPanel.js
// LimitedDecryptionPanel.js

$(document).ready(function() {
	var MAX_FILE_SIZE = 5 * 1024 * 1024 * 1024; // 5Gb
	var CHUNK_SIZE = 128 * 1024 * 1024; // 128 Mb
	const SIGNATURES = {v2_symmetric: "zDKO6XYXioc"};
	const encoder = new TextEncoder();
	const decoder = new TextDecoder();
	const extensionEnc = '.enc';
	
	var selectedFileEncrypt = null;
	var passwordEncrypt = null;
	var limitedIndex = null;
	var limitedSalt = null;
	var limitedKey = null;
	var limitedState = null;
	var limitedHeader = null;
	var limitedEncFileBuff = null;
	
	var selectedFileDecrypt = null;
	var passwordDecrypt = null;
	var limitedDecIndex = null;
	var limitedDecFileBuff = null;
	var limitedTestDecFileBuff = null;
	
	/*
	if (!window.Worker) {
		console.log("Worker not supported in your browser");
	}
	else {
		const worker = new Worker("sw.js");

		worker.onmessage = function (message) {
			console.log("Message received from worker");
			document.querySelector(".result").innerText =
			message.data.primes[message.data.primes.length - 1];
		};

		function doPointlessComputationsInWorker() {
			worker.postMessage({
				multiplier: multiplier,
				iterations: iterations,
			});
		}
		
		document.querySelector("button").onclick = doPointlessComputationsInWorker;
	}
	*/
		
	var printError = function(error, block) {
		$('#' + block).append(`<div class="error">${error.name}: ${error.message}</div>`);
	}
	
	const formatName = function(fileName) {
		//remove .enc
		let trimmed = fileName.replace(extensionEnc, "");
		//remove parenthesis
		let clean = trimmed.replace(/ *\([^)]*\) */g, "");

		return clean;
	};
	
	function cleanEncrypt() {
		selectedFileEncrypt = null;
		passwordEncrypt = null;
		limitedIndex = null;
		limitedSalt = null;
		limitedKey = null;
		limitedState = null;
		limitedHeader = null;
		limitedEncFileBuff = null;
	}
	
	function cleanDecrypt() {	
		selectedFileDecrypt = null;
		passwordDecrypt = null;
		limitedDecIndex = null;
		limitedDecFileBuff = null;
		limitedTestDecFileBuff = null;
	}
				
	// ==================== Encryption ==============================
	
	const limitedEncKeyGenerator = function(password) {
		limitedSalt = sodium.randombytes_buf(sodium.crypto_pwhash_SALTBYTES);

		limitedKey = sodium.crypto_pwhash(
			sodium.crypto_secretstream_xchacha20poly1305_KEYBYTES,
			password,
			limitedSalt,
			sodium.crypto_pwhash_OPSLIMIT_INTERACTIVE,
			sodium.crypto_pwhash_MEMLIMIT_INTERACTIVE,
			sodium.crypto_pwhash_ALG_ARGON2ID13
		);

		let limitedRes = sodium.crypto_secretstream_xchacha20poly1305_init_push(limitedKey);
		limitedState = limitedRes.state;
		limitedHeader = limitedRes.header;
	};
	
	const continueLimitedEncryption = function(file) {
		file.slice(limitedIndex, limitedIndex + CHUNK_SIZE)
			.arrayBuffer()
			.then((chunk) => {
				limitedIndex += CHUNK_SIZE;
				let limitedLast = limitedIndex >= file.size;
				
				if (!limitedLast) {
					$("#download_crypted .progress").html((Math.round(limitedIndex / file.size * 100)) + '%');
				}
				else {
					$("#download_crypted .progress").html('100%');
				}	

				limitedChunkEncryption(limitedLast, chunk, file);
			});
	};
	
	const handleEncryptedFileDownload = function() {
		
		let fileName = selectedFileEncrypt.name + extensionEnc;
		let blob = new Blob(limitedEncFileBuff);
		
		var url = window.URL.createObjectURL(blob);
		let link = document.createElement("a");
		link.href = url;
		link.download = fileName;
		
		$("#download_crypted .lds-ring").remove();
		$("#download_crypted .progress").remove();
		link.click();
		
		window.URL.revokeObjectURL(url);
		cleanEncrypt();
		$('#passwordEncrypt').val('');
		$('#encryptPanel .downloadPanel .success').append('<span class="message">Encrypting completed, download will start soon.</span>');
		$('#encryptPanel .downloadPanel .success').css('display', 'inline-block');
		$('#download_crypted').prop("disabled", false);
	};

	const handleFinishedEncryption = function() {
		handleEncryptedFileDownload();
	};
	
	const limitedChunkEncryption = function(limitedLast, chunk, file) {
		let limitedTag = limitedLast
			? sodium.crypto_secretstream_xchacha20poly1305_TAG_FINAL
			: sodium.crypto_secretstream_xchacha20poly1305_TAG_MESSAGE;

		const limitedEncryptedChunk =
			sodium.crypto_secretstream_xchacha20poly1305_push(
				limitedState,
				new Uint8Array(chunk),
				null,
				limitedTag
			);

		limitedEncFileBuff.push(new Uint8Array(limitedEncryptedChunk));

		if (limitedLast) {
			handleFinishedEncryption();
		}

		if (!limitedLast) {
		  continueLimitedEncryption(file);
		}
	};
	
	const startLimitedEncryption = function(file) {
		limitedEncKeyGenerator(passwordEncrypt);
					
		const SIGNATURE = new Uint8Array(encoder.encode(SIGNATURES["v2_symmetric"]));
		limitedEncFileBuff = []; //clear array
		limitedEncFileBuff.push(SIGNATURE);
		limitedEncFileBuff.push(limitedSalt);
		limitedEncFileBuff.push(limitedHeader);
		
		file.slice(0, CHUNK_SIZE).arrayBuffer().then((chunk) => {
			limitedIndex = CHUNK_SIZE;
			let limitedLast = limitedIndex >= file.size;
			limitedChunkEncryption(limitedLast, chunk, file);
		});
	};
	
	$('#download_crypted').click(function() {
		$('#errors_block_encrypt').hide();
		$('#errors_block_encrypt .error').remove();
		$('#encryptPanel .downloadPanel .success .message').remove();
		$('#encryptPanel .downloadPanel .success').hide();

		error = false;				
		passwordEncrypt = $('#passwordEncrypt').val();
	
		if (passwordEncrypt == '') {
			error = true;
			printError({name: 'Input error', message: 'please enter a password'}, 'errors_block_encrypt');
		}

		if (selectedFileEncrypt === null) {
			error = true;
			printError({name: 'Input error', message: 'please choose a file to encrypt'}, 'errors_block_encrypt');
		}
		
		if (error === false) {
			$('#download_crypted').append('<div class="lds-ring"><div></div><div></div><div></div><div></div></div>');
			$('#download_crypted').append('<div class="progress"></div>');
			$('#download_crypted').prop("disabled", true);
			startLimitedEncryption(selectedFileEncrypt);		
		}
		else {
			$('#errors_block_encrypt').show();
		}
	});

	const fileEncryptSelector = document.getElementById('encryptButton');

	fileEncryptSelector.addEventListener('change', (event) => {		
		const fileList = event.target.files;				
		selectedFileEncrypt = fileList[0];
		
		$('#errors_block_encrypt').hide();
		$('#errors_block_encrypt .error').remove();
		
		if (selectedFileEncrypt.size > MAX_FILE_SIZE) {
			$('#errors_block_encrypt').show();
			printError({name: 'Input error', message: 'Selected file is too big (max 5Gb)'}, 'errors_block_encrypt');
			selectedFileEncrypt = null;
		}
	});
	
	// ==================== Decryption ==============================
	
	const limitedDecKeyGenerator = function(password, salt, header) {
		let limitedDecSalt = new Uint8Array(salt);
		let limitedDecHeader = new Uint8Array(header);

		let limitedDecKey = sodium.crypto_pwhash(
		  sodium.crypto_secretstream_xchacha20poly1305_KEYBYTES,
		  password,
		  limitedDecSalt,
		  sodium.crypto_pwhash_OPSLIMIT_INTERACTIVE,
		  sodium.crypto_pwhash_MEMLIMIT_INTERACTIVE,
		  sodium.crypto_pwhash_ALG_ARGON2ID13
		);

		let limitedDecState =
		  sodium.crypto_secretstream_xchacha20poly1305_init_pull(
			limitedDecHeader,
			limitedDecKey
		  );

		if (limitedDecState) {
		  startLimitedDecryption(limitedDecState);
		}
	};
			
	const handleDecryptedFileDownload = function() {
		let fileName = formatName(selectedFileDecrypt.name);

		let blob = new Blob(limitedDecFileBuff);

		var url = window.URL.createObjectURL(blob);
		let link = document.createElement("a");
		link.href = url;
		link.download = fileName;
		
		$("#download_decrypted .lds-ring").remove();
		$("#download_decrypted .progress").remove();
		link.click();
		
		window.URL.revokeObjectURL(url);
		cleanDecrypt();
		
		$('#passwordDecrypt').val('');
		$('#decryptPanel .downloadPanel .success').append('<span class="message">Decrypting completed, download will start soon.</span>');
		$('#decryptPanel .downloadPanel .success').css('display', 'inline-block');
		$('#download_decrypted').prop("disabled", false);
	};

	const handleFinishedDecryption = function() {
		handleDecryptedFileDownload();
	};
	
	const continueLimitedDecryption = (dec_state) => {
		file = selectedFileDecrypt;

		file.slice(
			limitedDecIndex,
			limitedDecIndex +
			CHUNK_SIZE +
			sodium.crypto_secretstream_xchacha20poly1305_ABYTES
			)
			.arrayBuffer()
			.then((chunk) => {
				limitedDecIndex +=
				CHUNK_SIZE + sodium.crypto_secretstream_xchacha20poly1305_ABYTES;
				let limitedDecLast = limitedDecIndex >= file.size;
				if (!limitedDecLast) {
					$("#download_decrypted .progress").html((Math.round(limitedDecIndex / file.size * 100)) + '%');
				}
				else {
					$("#download_decrypted .progress").html('100%');
				}	
				
				limitedChunkDecryption(limitedDecLast, chunk, dec_state);
		});
	};
	
	const limitedChunkDecryption = function(limitedDecLast, chunk, dec_state) {
		let limitedDecResult = sodium.crypto_secretstream_xchacha20poly1305_pull(
			dec_state,
			new Uint8Array(chunk)
		);

		if (limitedDecResult) {
			let limitedDecryptedChunk = limitedDecResult.message;

			limitedDecFileBuff.push(new Uint8Array(limitedDecryptedChunk));

			if (limitedDecLast) {
				handleFinishedDecryption();
			}
			if (!limitedDecLast) {
				continueLimitedDecryption(dec_state);
			}
		}
		else {
			// Error wrong password
			$('#errors_block_decrypt').hide();
			$('#errors_block_decrypt .error').remove();
			$("#download_decrypted .lds-ring").remove();
			$('#download_decrypted').prop("disabled", false);
			printError({name: 'Decrypting', message: 'Password is incorrect'}, 'errors_block_decrypt');
		}
	};
	
	const startLimitedDecryption = (dec_state) => {
		let startIndex;
		startIndex = 51;

		limitedDecFileBuff = [];

		file = selectedFileDecrypt;

		file
		  .slice(
			startIndex,
			startIndex + CHUNK_SIZE + sodium.crypto_secretstream_xchacha20poly1305_ABYTES
		  )
		  .arrayBuffer()
		  .then((chunk) => {
			limitedDecIndex =
			  startIndex +
			  CHUNK_SIZE +
			  sodium.crypto_secretstream_xchacha20poly1305_ABYTES;
			let limitedDecLast = limitedDecIndex >= file.size;
			limitedChunkDecryption(limitedDecLast, chunk, dec_state);
		  });
		};
		
	const testLimitedDecryption = function(file) {
	
		$('#errors_block_decrypt').hide();
		$('#errors_block_decrypt .error').remove();

		Promise.all([
		file.slice(11, 27).arrayBuffer(), //salt
		file.slice(27, 51).arrayBuffer(), //header
		file
			.slice(
			51,
			51 +
			CHUNK_SIZE +
			sodium.crypto_secretstream_xchacha20poly1305_ABYTES
		)
		.arrayBuffer(),
		]).then(([limitedTestSalt, limitedTestHeader, limitedTestChunk]) => {
			limitedTestDecFileBuff = limitedTestChunk; //for testing the dec password

			let decLimitedTestsalt = new Uint8Array(limitedTestSalt);
			let decLimitedTestheader = new Uint8Array(limitedTestHeader);

			let decLimitedTestKey = sodium.crypto_pwhash(
				sodium.crypto_secretstream_xchacha20poly1305_KEYBYTES,
				passwordDecrypt,
				decLimitedTestsalt,
				sodium.crypto_pwhash_OPSLIMIT_INTERACTIVE,
				sodium.crypto_pwhash_MEMLIMIT_INTERACTIVE,
				sodium.crypto_pwhash_ALG_ARGON2ID13
			);

			let limitedTestState =
				sodium.crypto_secretstream_xchacha20poly1305_init_pull(
				decLimitedTestheader,
				decLimitedTestKey
			);

			if (limitedTestState) {
				let decLimitedTestresults =
				sodium.crypto_secretstream_xchacha20poly1305_pull(
					limitedTestState,
					new Uint8Array(limitedTestDecFileBuff)
				);
				if (decLimitedTestresults) {
					limitedDecKeyGenerator(
						passwordDecrypt,
						limitedTestSalt,
						limitedTestHeader
					);
				}
				else {
					// Error wrong password
					$('#errors_block_decrypt').show();
					$("#download_decrypted .lds-ring").remove();
					$('#download_decrypted').prop("disabled", false);
					printError({name: 'Decrypting', message: 'password is incorrect'}, 'errors_block_decrypt');
				}
			}
		});
	}
	
	$('#download_decrypted').click(function() {		
		$('#errors_block_decrypt').hide();
		$('#errors_block_decrypt .error').remove();
		$('#decryptPanel .downloadPanel .success .message').remove();
		$('#decryptPanel .downloadPanel .success').hide();

		error = false;				
		passwordDecrypt = $('#passwordDecrypt').val();		
	
		if (passwordDecrypt == '') {
			error = true;
			printError({name: 'Input error', message: 'please enter a password'}, 'errors_block_decrypt');
		}

		if (selectedFileDecrypt === null) {
			error = true;
			printError({name: 'Input error', message: 'please chose a file to decrypt'}, 'errors_block_decrypt');
		}
		
		if (error === false) {
			$('#download_decrypted').append('<div class="lds-ring"><div></div><div></div><div></div><div></div></div>');
			$('#download_decrypted').append('<div class="progress"></div>');
			$('#download_decrypted').prop("disabled", true);
			testLimitedDecryption(selectedFileDecrypt);
		}
		else {
			$('#errors_block_decrypt').show();
		}
	});
					
	const fileDecryptSelector = document.getElementById('decryptButton');

	fileDecryptSelector.addEventListener('change', (event) => {		
		const fileList = event.target.files;				
		selectedFileDecrypt = fileList[0];
		
		$('#errors_block_decrypt').hide();
		$('#errors_block_decrypt .error').remove();
		
		var error = false;
		
		if (selectedFileDecrypt.size > MAX_FILE_SIZE) {
			$('#errors_block_decrypt').show();
			selectedFileDecrypt = null;
			printError({name: 'Input error', message: 'Selected file is too big (max 5Gb)'}, 'errors_block_decrypt');
		}
		
		// Check signature
		Promise.all([selectedFileDecrypt.slice(0, 11).arrayBuffer()]).then(([sig]) => {
			if (decoder.decode(sig) !== SIGNATURES["v2_symmetric"]) {
				$('#errors_block_decrypt').show();
				selectedFileDecrypt = null;
				printError({name: 'Input error',
				message: "File uploaded hasn't been generated by this service or is corrupted (expected signature=" + SIGNATURES["v2_symmetric"] + ")"},
				'errors_block_decrypt');
			}
		});

	});
	
});