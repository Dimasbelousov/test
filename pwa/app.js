// SW reg
// if ('serviceWorker' in navigator) {
//     navigator.serviceWorker.register('/sw.js')
//         .then(() => console.log('Service Worker registered'))
//         .catch(err => console.error('Service Worker registration failed:', err));
// }
const STORAGE_CREDENTIAL_ID_KEY = 'webauthnCredentialId';
const DB_VERSION = 3;

if ('serviceWorker' in navigator) {
    navigator.serviceWorker.register('/sw.js')
        .then(() => {
            console.log('Service Worker registered'); // Логирование в консоль
            // Добавляем текст в тег на странице
            const statusElement = document.getElementById('service-worker-status');
            if (statusElement) {
                statusElement.textContent = 'Service Worker успешно зарегистрирован!';
            }
        })
        .catch(err => {
            console.error('Service Worker registration failed:', err); // Логирование ошибки
            // Добавляем текст об ошибке в тег на странице
            const statusElement = document.getElementById('service-worker-status');
            if (statusElement) {
                statusElement.textContent = 'Ошибка регистрации Service Worker: ' + err.message;
            }
        });
}

// SID sipher with PBKDF2
async function generateKeyFromPassword(password, salt) {
    const encoder = new TextEncoder();
    const passwordBuffer = encoder.encode(password);
    const saltBuffer = encoder.encode(salt);

    const baseKey = await crypto.subtle.importKey(
        "raw",
        passwordBuffer,
        { name: "PBKDF2" },
        false,
        ["deriveKey"]
    );

    return crypto.subtle.deriveKey(
        {
            name: "PBKDF2",
            salt: saltBuffer,
            iterations: 100000,
            hash: "SHA-256"
        },
        baseKey,
        { name: "AES-GCM", length: 256 },
        true,
        ["encrypt", "decrypt"]
    );
}

// Шифрование данных
async function encryptData(key, data) {
    const encoder = new TextEncoder();
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const encryptedData = await crypto.subtle.encrypt(
        {
            name: "AES-GCM",
            iv: iv
        },
        key,
        encoder.encode(data)
    );

    return {
        iv: Array.from(iv),
        encryptedData: Array.from(new Uint8Array(encryptedData))
    };
}

// Расшифровка данных
async function decryptData(key, encryptedData, iv) {
    try {
        const decryptedData = await crypto.subtle.decrypt(
            {
                name: "AES-GCM",
                iv: new Uint8Array(iv)
            },
            key,
            new Uint8Array(encryptedData)
        );

        const decoder = new TextDecoder();
        return decoder.decode(decryptedData);
    } catch (error) {
        console.error("Ошибка аутентификации по паролю:", error);
        throw error;
    }
}

// Сохранение ключа в IndexedDB
function saveKeyToIndexedDB(key, salt, startVector) {
    const request = indexedDB.open('PwaIndexedDB', DB_VERSION); // Увеличена версия базы

    request.onupgradeneeded = (event) => {
        const db = event.target.result;
        if (!db.objectStoreNames.contains('keys')) {
            db.createObjectStore('keys', { keyPath: 'id', autoIncrement: true });
        }
    };

    request.onsuccess = (event) => {
        const db = event.target.result;
        const transaction = db.transaction('keys', 'readwrite');
        const store = transaction.objectStore('keys');
        const cryptoData = {
            key: key,
            salt: salt,
            startVector: startVector,
            timestamp: new Date().toISOString()
        }
        store.add(cryptoData);
        console.log('Key saved to IndexedDB');
    };

    request.onerror = (event) => {
        console.error('Error opening IndexedDB:', event.target.error);
    };
}

// Получение ключа из IndexedDB
function getKeyFromIndexedDB() {
    return new Promise((resolve, reject) => {
        const request = indexedDB.open('PwaIndexedDB', DB_VERSION); 

        request.onupgradeneeded = (event) => { // Добавлен обработчик для создания хранилища
            const db = event.target.result;
            if (!db.objectStoreNames.contains('keys')) {
                db.createObjectStore('keys', { keyPath: 'id', autoIncrement: true });
            }
        };

        request.onsuccess = (event) => {
            const db = event.target.result;
            if (!db.objectStoreNames.contains('keys')) { // Проверка существования хранилища
                reject('Object store "keys" does not exist');
                return;
            }
            const transaction = db.transaction('keys', 'readonly');
            const store = transaction.objectStore('keys');
            const query = store.getAll();

            query.onsuccess = () => {
                if (query.result.length > 0) {
                    const latest = query.result.reduce((a, b) => 
                        a.timestamp > b.timestamp ? a : b
                    );
                    resolve({
                        key: latest.key,
                        salt: latest.salt,
                        startVector: latest.startVector
                    });
                } else {
                    resolve(null);
                }
            };

            query.onerror = () => {
                reject('Error retrieving key from IndexedDB');
            };
        };

        request.onerror = (event) => {
            reject('Error opening IndexedDB: ' + event.target.error);
        };
    });
}

// проверить, не пустая ли запись в базе IndexedDB
function validateCryptoData(data) {
    return data && 
           data.key &&
           data.salt && 
           data.startVector;
}


function generateRandomBuffer(length = 32) {
    const buffer = new Uint8Array(length);
    crypto.getRandomValues(buffer);
    return buffer;
}

  // Преобразование строки в ArrayBuffer (UTF-8)
function stringToArrayBuffer(str) {
    return new TextEncoder().encode(str);
}

  // Преобразование ArrayBuffer в строку (UTF-8)
function arrayBufferToString(buffer) {
    return new TextDecoder().decode(buffer);
}

  // Помогает декодировать base64url в ArrayBuffer (для allowCredentials.id)
function base64UrlDecode(input) {
    let base64 = input.replace(/-/g, '+').replace(/_/g, '/');
    // добавляем паддинг, если необходимо
    while (base64.length % 4) {
        base64 += '=';
    }
    const binaryString = window.atob(base64);
    const len = binaryString.length;
    const bytes = new Uint8Array(len);
    for (let i = 0; i < len; i++) {
        bytes[i] = binaryString.charCodeAt(i);
    }
    return bytes.buffer;
}

  // Помогает кодировать ArrayBuffer в base64url (для хранения credential.id)
function base64UrlEncode(buffer) {
    const bytes = new Uint8Array(buffer);
    let binary = '';
    for (let i = 0; i < bytes.byteLength; i++) {
        binary += String.fromCharCode(bytes[i]);
    }
    const base64 = window.btoa(binary);
    return base64.replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}


async function enroll(seedString) {
    // Преобразуем seed в ArrayBuffer
    console.log("keeeey: ", seedString)
    const seedBuffer = stringToArrayBuffer(seedString);
    // генерируем публичный ключ
    const publicKey = {
        rp: { name: 'Example RP', id: window.location.hostname },
        user: {
            id: Uint8Array.from(String(Math.random()*999999999), c => c.charCodeAt(0)),
            name: 'user@icloud.com',
            displayName: 'test user'
        },
        challenge: Uint8Array.from('Data to sign', (c) => c.charCodeAt(0)),
        pubKeyCredParams: [
            { type: 'public-key', alg: -7 }, // алгоритм ES256
            { type: 'public-key', alg: -257}, // RS256
        ],
        authenticatorSelection: {
            authenticatorAttachment: 'platform', // Используем встроенный аутентификатор (например, TouchID/FaceID)
            userVerification: 'required',
            residentKey: 'required',
        },
        // Передаём расширение largeBlob: устанавливаем поддержку
        extensions: {
            largeBlob: { support: 'required', }
        }
    };

    try {
      // Запускаем процесс регистрации, вызывается системный диалог для биометрии
        const credential = await navigator.credentials.create({ publicKey });
        if (!credential) {
            throw new Error("Не удалось создать учётные данные.");
        }
        console.log("LargeBlob вернул объект:", credential.getClientExtensionResults().largeBlob.supported);
        console.log("Host:", window.location.hostname)
      // Сохраняем идентификатор учётных данных (в base64url) для последующей аутентификации
        const credId = base64UrlEncode(credential.rawId);
        localStorage.setItem(STORAGE_CREDENTIAL_ID_KEY, credId);
        console.log("Регистрация успешна. Credential ID сохранён:", credId, credential.rawId);

        const second = await navigator.credentials.get({
            publicKey: {
                challenge: Uint8Array.from('Data to sign', (c) => c.charCodeAt(0)),
                timeout: 60000,
                userVerification: "required",
                allowCredentials: [{
                    type: "public-key",
                    id: credential.rawId,
                    transports: ['internal'],
                }],
                // Записываем в расширение largeBlob
                extensions: {
                    largeBlob: {
                        write: seedBuffer}
            }
        }})
        console.log("LargeBlob записан:", second.getClientExtensionResults().largeBlob.written);
        return second;
    } catch (error) {
        console.error("Ошибка регистрации с largeBlob:", error);
        throw error;
    }
}


async function authenticateAndRetrieveSeed() {
    const storedCredId = localStorage.getItem(STORAGE_CREDENTIAL_ID_KEY);
    if (!storedCredId) {
        throw new Error("Учётные данные не найдены. Сначала выполните регистрацию (enroll).");
    }

    // Преобразуем сохранённый идентификатор в ArrayBuffer
    const credIdBuffer = base64UrlDecode(storedCredId);
    console.log("blobID:", storedCredId, credIdBuffer)

    const publicKey = {
        challenge: Uint8Array.from('Data to sign', (c) => c.charCodeAt(0)),
        timeout: 60000,
        userVerification: "required",
        allowCredentials: [{
            type: "public-key",
            id: credIdBuffer,
            transports: ['internal']
      }],
      // Запрашиваем расширение largeBlob (true означает, что мы ожидаем его получить)
        extensions: {
            largeBlob: {
                read: true}
      }
    };

    try {
      // Запускаем процесс аутентификации – системный диалог биометрии
        const assertion = await navigator.credentials.get({ publicKey });
        if (!assertion) {
            throw new Error("Аутентификация не выполнена.");
        }
      // Получаем результаты расширений. Ожидаем, что расширение largeBlob вернёт сохранённый seed
        const extResults = assertion.getClientExtensionResults();
        if (!extResults.largeBlob.blob) {
            throw new Error("Расширение largeBlob не получено.");
        }
      // Преобразуем полученный ArrayBuffer в строку
        const seedString = arrayBufferToString(extResults.largeBlob.blob);
        console.log("Аутентификация успешна. Получен seed:", seedString);
        return { seedString, assertion };
    } catch (error) {
        console.error("Ошибка аутентификации с largeBlob:", error);
        throw error;
    }
}

// Проверка поддержки Large Blob
async function isLargeBlobSupported() {
    return PublicKeyCredential &&
        (await PublicKeyCredential.isUserVerifyingPlatformAuthenticatorAvailable()) &&
        (await PublicKeyCredential.isConditionalMediationAvailable());
}



//надо добавить такую штуку что когда уже есть информация в бд то локал сторедж проеряем и создаем биом
// Обработчик кнопки
document.getElementById('encryptBtn').addEventListener('click', async () => {
    const password = document.getElementById('password').value;
    document.getElementById('output').textContent = '';
    document.getElementById('app-worker-status').textContent = '';
    // Проверяем, есть ли ключ в IndexedDB и поддерживается ли биометрия
    const existingKey = await getKeyFromIndexedDB();
    const biomSupported = await isLargeBlobSupported();
    const storeCredId = localStorage.getItem(STORAGE_CREDENTIAL_ID_KEY);

    // Получаем данные из Service Worker, а именно в первый раз сгенерированную соль и сид
    const registration = await navigator.serviceWorker.ready;
    registration.active.postMessage({ type: 'getData' });

    let receivedSalt, receivedData; 
    ({ salt: receivedSalt, data: receivedData } = await new Promise((resolve) => {
        navigator.serviceWorker.onmessage = (event) => resolve(event.data);
    }));


    if (!password && (!biomSupported || storeCredId === null)) {
        const statusElement = document.getElementById('app-worker-status');
            if (statusElement) {
                statusElement.textContent = 'Введите PIN-Code, у вас либо не сохранена биометрия либо она недоступна';
            }
        throw new Error('Password is required, Biometry unavailable');

    } else if (!biomSupported && password) {

        if (existingKey  && validateCryptoData(existingKey)) {
            //биометрия недоступна и данные уже есть в бд
            receivedSalt = existingKey.salt;
            key = await generateKeyFromPassword(password, receivedSalt);
            decryptData(key, existingKey.key, existingKey.startVector).then(decryptedData => {
                    document.getElementById('output').textContent = `Decrypted Data: ${decryptedData}`;
                }).catch(error => {
                    console.error("Неверный пароль, повторите ввод", error);
                    document.getElementById('app-worker-status').textContent = 'Неверный ввод пароля';
        });

        } else if (!existingKey) {
            //биометрия недоступна и нет ключа - шифруем
            const key = await generateKeyFromPassword(password, receivedSalt);
            console.log('Ключа не было, сгенерили его и тут нет биометрии', key, receivedData);
            // Если ключа нет, шифруем данные и сохраняем ключ
            const encrypted = await encryptData(key, receivedData);
            saveKeyToIndexedDB(encrypted.encryptedData, receivedSalt, encrypted.iv);
            document.getElementById('output').textContent = `Encrypted Data: ${JSON.stringify(encrypted, null, 2)}`;

        } else {
            const statusElement = document.getElementById('app-worker-status');
            statusElement.textContent = 'Неверно сохранилась инфрмация в бд: ' + err.message;
            throw new Error('Invalid key format in IndexedDB');
        }
    } else if (biomSupported && password) {

        if (storeCredId != null && existingKey && validateCryptoData(existingKey)) {
            // пользователь ранее входил и в локал сторедже лежит звголовок для блоба>>>> const decryptedData = await 
            receivedSalt = existingKey.salt;
            key = await generateKeyFromPassword(password, receivedSalt);
            decryptData(key, existingKey.key, existingKey.startVector).then(decryptedData => {
                    document.getElementById('output').textContent = `Decrypted Data: ${decryptedData}`;
            }).catch(error => {
                    console.error("Неверный пароль, повторите ввод", error);
                    document.getElementById('app-worker-status').textContent = 'Неверный ввод пароля';
            });
        
        } else if (storeCredId === null && existingKey && validateCryptoData(existingKey)) {
            // посчитать ключ, расшифровать и предложить биометрию с укладкой в блоб ключа
            receivedSalt = existingKey.salt;
            const storedseq = JSON.stringify({pass: password, salt: receivedSalt});
            enroll(storedseq).then(second => {
                    console.log("Учётные данные успешно созданы:", second);
                }).catch(err => {
                    console.error("Ошибка при регистрации:", err);
                });
            key = await generateKeyFromPassword(password, receivedSalt);
            decryptData(key, existingKey.key, existingKey.startVector).then(decryptedData => {
                    document.getElementById('output').textContent = `Decrypted Data: ${decryptedData}`;
                }).catch(error => {
                    console.error("Неверный пароль, повторите ввод", error);
                    document.getElementById('app-worker-status').textContent = 'Неверный ввод пароля';
        });

        } else if (!existingKey) {
            const storedseq = JSON.stringify({pass: password, salt: receivedSalt});
            enroll(storedseq).then(second => {
                console.log("Учётные данные успешно созданы:", second);
            }).catch(err => {
                console.error("Ошибка при регистрации:", err);
            });
            key = await generateKeyFromPassword(password, receivedSalt);
            const encrypted = await encryptData(key, receivedData);
            saveKeyToIndexedDB(encrypted.encryptedData, receivedSalt, encrypted.iv);
            document.getElementById('output').textContent = `Encrypted Data: ${JSON.stringify(encrypted, null, 2)}`;
        }
    } else if (biomSupported && !password) {

        if (storeCredId != null && existingKey && validateCryptoData(existingKey)) {
            //случай когда все уже есть и пользователь входит по биометрии
            authenticateAndRetrieveSeed().then(({ seedString, assertion }) => {
                    console.log("Полученный seed:", seedString, 'assertion:', assertion);
                    let concat_line = JSON.parse(seedString);
                    let pass = concat_line.pass;
                    receivedSalt = concat_line.salt;
                    // Далее можно использовать seed для генерации симметричного ключа и шифрования/расшифровки данных.
                    return generateKeyFromPassword(pass, receivedSalt);
                }).then((key) => {
                    return decryptData(key, existingKey.key, existingKey.startVector);
                }).then((decryptedData) => {
                    console.log("data was decrypted");
                    document.getElementById('output').textContent = `Decrypted Data: ${decryptedData}`;
                })
                .catch(err => {
                    console.error("Ошибка биометрии:", err);
                });
        }
    } else {
        const statusElement = document.getElementById('app-worker-status');
        statusElement.textContent = 'Необработанная ошибка';
        throw new Error('Invalid key format in IndexedDB');
    }
});