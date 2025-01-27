# libsodium-encrypt-decrypt-files
Encrypt / decrypt files with a password with libsodium.js in your browser.

libsodium.js : browsers-sumo file https://github.com/jedisct1/libsodium.js/blob/master/dist/browsers-sumo/sodium.js

It's a simple version of https://hat.sh/ service, you can find source code here https://github.com/sh-dv/hat.sh<br /><br/>
For writing files, File System Access API is used (no limit of file size) or blob (RAM memory limit) as a fallback for not supported browsers.<br />
See list : https://developer.mozilla.org/en-US/docs/Web/API/Window/showSaveFilePicker#browser_compatibility

Functions used : sodium.crypto_secretstream_xchacha20poly1305_*

Constants :<br />
MAX_FILE_SIZE = 5 * 1024 * 1024 * 1024; // 5Gb<br />
CHUNK_SIZE = 128 * 1024 * 1024; // 128 Mb<br />
SIGNATURES = {v2_symmetric: "zDKO6XYXioc"};<br />
const extensionEnc = '.enc';<br />
