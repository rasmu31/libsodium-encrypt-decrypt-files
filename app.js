// Adaptation of https://github.com/sh-dv/hat.sh/
// LimitedEncryptionPanel.js
// LimitedDecryptionPanel.js

// I added support of File System API https://developer.chrome.com/docs/capabilities/web-apis/file-system-access#write-file
// To support browsers not handling File System API, see web worker implementation in project https://github.com/jimmywarting/native-file-system-adapter

$(document).ready(function() {	
	
	var MAX_FILE_SIZE = 5 * 1024 * 1024 * 1024; // 5Gb
	var CHUNK_SIZE = 16 * 1024 * 1024; // 256 Mb
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
	var fileHandleEncrypt = null;
	
	var selectedFileDecrypt = null;
	var passwordDecrypt = null;
	var limitedDecIndex = null;
	var limitedDecFileBuff = null;
	var limitedTestDecFileBuff = null;
	var fileHandleDecrypt = null;
		
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
	
	const supportsFileSystemAccess = function() {
		if ('showSaveFilePicker' in window) {
			try {
				return window.self === window.top;
			}
			catch {
				return false;
			}
		}
		return false;
	};
	
	async function getNewFileHandle(filename) {
		handle = null;
		
		try {
			handle = await window.showSaveFilePicker({suggestedName: filename});
		}
		catch (err) {

		}
					
		return handle;
	}

	async function writeFile(fileHandle, contents) {
		// Create a FileSystemWritableFileStream to write to.
		const size = (await fileHandle.getFile()).size;
		
		const writable = await fileHandle.createWritable({keepExistingData:true});
		// Write the contents of the file to the stream.
		await writable.write({type: 'write', data: contents, position: size});
		// Close the file and write the contents to disk.
		await writable.close();
		
		contents = null;
	}
	
	// ==================== Init ====================================
	
	var isSupportedFileSystemAccess = supportsFileSystemAccess();
	textversion = 'Your brower doesn\'t support v2, v1 will be used (file size limited to RAM memory available, 5Gb maximum).';
	if (isSupportedFileSystemAccess)
		textversion = 'Your browser is compatible with v2, only size of your hard drive free space will matter.';
		
	$('#version-implementation').html(textversion);
				
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
				
				limitedChunkEncryption(limitedLast, chunk, file);
				
				if (!limitedLast) {
					$("#download_crypted .progress").html((Math.round(limitedIndex / file.size * 100)) + '%');
				}
				else {
					$("#download_crypted .progress").html('100%');
				}				
			});
	};
	
	const handleEncryptedFileDownload = function() {		
		if (isSupportedFileSystemAccess) {
			// Download is finished for sure
			
			$('#encryptPanel .downloadPanel .success').append('<span class="message">Download is complete.</span>');
			
			fileHandleEncrypt = null;
		}
		else {
			let fileName = selectedFileEncrypt.name + extensionEnc;
			let blob = new Blob(limitedEncFileBuff);	
			var url = window.URL.createObjectURL(blob);
			let link = document.createElement("a");
			link.href = url;
			link.download = fileName;
			
			link.click();
			window.URL.revokeObjectURL(url);
			$('#encryptPanel .downloadPanel .success').append('<span class="message">Encrypting completed, download will start soon.</span>');
		}
		
		cleanEncrypt();
		$("#download_crypted .lds-ring").remove();
		$("#download_crypted .progress").remove();
		$('#passwordEncrypt').val('');
		$('#encryptButton').val('');
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

		limitedEncryptedChunk =
			sodium.crypto_secretstream_xchacha20poly1305_push(
				limitedState,
				new Uint8Array(chunk),
				null,
				limitedTag
			);
		
		if (isSupportedFileSystemAccess) {
			Promise.all([writeFile(fileHandleEncrypt, new Uint8Array(limitedEncryptedChunk))]).then(([success]) => {
				limitedEncryptedChunk = null;
				if (limitedLast) {
					handleFinishedEncryption();
				}

				if (!limitedLast) {
					continueLimitedEncryption(file);
				}
			});
		}
		else {
			limitedEncFileBuff.push(new Uint8Array(limitedEncryptedChunk));
			if (limitedLast) {
				handleFinishedEncryption();
			}

			if (!limitedLast) {
			  continueLimitedEncryption(file);
			}
		}
		
	};
	
	const startLimitedEncryption = function(file) {
		limitedEncKeyGenerator(passwordEncrypt);
					
		const SIGNATURE = new Uint8Array(encoder.encode(SIGNATURES["v2_symmetric"]));
		limitedEncFileBuff = []; //clear array
		limitedEncFileBuff.push(SIGNATURE);
		limitedEncFileBuff.push(limitedSalt);
		limitedEncFileBuff.push(limitedHeader);
				
		if (isSupportedFileSystemAccess) {
			Promise.all([writeFile(fileHandleEncrypt, new Blob(limitedEncFileBuff))]).then(([success]) => {
				file.slice(0, CHUNK_SIZE).arrayBuffer().then((chunk) => {
					limitedEncFileBuff = null;
					$("#download_crypted .progress").html('0%');
					limitedIndex = CHUNK_SIZE;
					let limitedLast = limitedIndex >= file.size;
					limitedChunkEncryption(limitedLast, chunk, file);
				});
			});
				
		}
		else {
			file.slice(0, CHUNK_SIZE).arrayBuffer().then((chunk) => {
				limitedIndex = CHUNK_SIZE;
				let limitedLast = limitedIndex >= file.size;
				limitedChunkEncryption(limitedLast, chunk, file);
			});
		}
	};
	
	$('#download_crypted').click(async function() {
		$('#errors_block_encrypt').hide();
		$('#errors_block_encrypt .error').remove();
		$('#encryptPanel .downloadPanel .success .message').remove();
		$('#encryptPanel .downloadPanel .success').hide();

		error = false;				
		passwordEncrypt = $('#passwordEncrypt').val();
	
		if (passwordEncrypt == '') {
			error = true;
			printError({name: 'Input error', message: 'please enter a password.'}, 'errors_block_encrypt');
		}

		if (selectedFileEncrypt === null) {
			error = true;
			printError({name: 'Input error', message: 'please choose a file to encrypt.'}, 'errors_block_encrypt');
		}
		
		if (error === false) {
			if (isSupportedFileSystemAccess) {
				let fileName = selectedFileEncrypt.name + extensionEnc;
				fileHandleEncrypt = await getNewFileHandle(fileName);
				if (fileHandleEncrypt === null) {
					error = true;
					printError({name: 'Input error', message: 'please choose the folder where encrypted file will be saved.'}, 'errors_block_encrypt');
				}
			}
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
		
		if (!isSupportedFileSystemAccess) {
			if (selectedFileEncrypt.size > MAX_FILE_SIZE) {
				$('#errors_block_encrypt').show();
				printError({name: 'Input error', message: 'file to encrypt is too big (5Gb maximum)'}, 'errors_block_encrypt');
				selectedFileEncrypt = null;
			}
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
		if (isSupportedFileSystemAccess) {
			// Download is finished for sure
			
			$('#decryptPanel .downloadPanel .success').append('<span class="message">Download is complete.</span>');
			
			fileHandleDecrypt = null;
		}
		else {
			let fileName = formatName(selectedFileDecrypt.name);			
			let blob = new Blob(limitedDecFileBuff);
			var url = window.URL.createObjectURL(blob);
			let link = document.createElement("a");
			link.href = url;
			link.download = fileName;
						
			link.click();
			window.URL.revokeObjectURL(url);
			$('#decryptPanel .downloadPanel .success').append('<span class="message">Decrypting is over, download will start soon.</span>');
		}
		
		cleanDecrypt();
		$("#download_decrypted .lds-ring").remove();
		$("#download_decrypted .progress").remove();
		$('#passwordDecrypt').val('');
		$('#decryptButton').val('');
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
				
				limitedChunkDecryption(limitedDecLast, chunk, dec_state);
				
				if (!limitedDecLast) {
					$("#download_decrypted .progress").html((Math.round(limitedDecIndex / file.size * 100)) + '%');
				}
				else {
					$("#download_decrypted .progress").html('100%');
				}
		});
	};
	
	const limitedChunkDecryption = function(limitedDecLast, chunk, dec_state) {
		let limitedDecResult = sodium.crypto_secretstream_xchacha20poly1305_pull(
			dec_state,
			new Uint8Array(chunk)
		);

		if (limitedDecResult) {
			let limitedDecryptedChunk = limitedDecResult.message;

			if (isSupportedFileSystemAccess) {
				Promise.all([writeFile(fileHandleDecrypt, new Uint8Array(limitedDecryptedChunk))]).then(([success]) => {
					limitedDecryptedChunk = null;
					if (limitedDecLast) {
						handleFinishedDecryption();
					}
					if (!limitedDecLast) {
						continueLimitedDecryption(dec_state);
					}		
				});
			}
			else {
				limitedDecFileBuff.push(new Uint8Array(limitedDecryptedChunk));
				if (limitedDecLast) {
					handleFinishedDecryption();
				}
				if (!limitedDecLast) {
					continueLimitedDecryption(dec_state);
				}
			}			
		}
		else {
			// Error wrong password
			$('#errors_block_decrypt').hide();
			$('#errors_block_decrypt .error').remove();
			$("#download_decrypted .lds-ring").remove();
			$('#download_decrypted').prop("disabled", false);
			printError({name: 'Decrypting', message: 'password is incorrect'}, 'errors_block_decrypt');
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
	
	$('#download_decrypted').click(async function() {		
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
			printError({name: 'Input error', message: 'please choose a file to decrypt'}, 'errors_block_decrypt');
		}
		
		if (error === false) {
			if (isSupportedFileSystemAccess) {
				let fileName = formatName(selectedFileDecrypt.name);
				fileHandleDecrypt = await getNewFileHandle(fileName);
				if (fileHandleDecrypt === null) {
					error = true;
					printError({name: 'Input error', message: 'please choose the folder where decrypted file will be saved'}, 'errors_block_decrypt');
				}
			}
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
		
		if (!isSupportedFileSystemAccess) {
			if (selectedFileDecrypt.size > MAX_FILE_SIZE) {
				$('#errors_block_decrypt').show();
				selectedFileDecrypt = null;
				printError({name: 'Input error', message: 'file to decrypt is too big (5Gb maximum)'}, 'errors_block_decrypt');
			}
		}
		
		// Check signature
		Promise.all([selectedFileDecrypt.slice(0, 11).arrayBuffer()]).then(([sig]) => {
			if (decoder.decode(sig) !== SIGNATURES["v2_symmetric"]) {
				$('#errors_block_decrypt').show();
				selectedFileDecrypt = null;
				printError({name: 'Input error',
				message: "file to decrypt hasn't been generated with this service or is corrupted (expected signature =" + SIGNATURES["v2_symmetric"] + ")."},
				'errors_block_decrypt');
			}
		});

	});
	
});