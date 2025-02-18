// SID gen
function generateRandomString(length = 20) {
    const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
    let result = '';
    for (let i = 0; i < length; i++) {
        result += chars.charAt(Math.floor(Math.random() * chars.length));
    }
    return result;
}

// Генерация соли
const salt = crypto.randomUUID(); // Уникальная соль
//const data = generateRandomString(); // Случайная строка
const data = new String("796asfasf8a0sf70af97");

const CACHE_NAME = 'pwa-encryption-app-v1';
const STATIC_FILES = [
    '/',
    '/index.html',
    '/style.css',
    '/app.js',
    '/manifest.json',
    '/sw.js'
];

// Установка Service Worker и кэширование статических файлов
self.addEventListener('install', (event) => {
    console.log('Service Worker installing...');
    event.waitUntil(
        caches.open(CACHE_NAME).then((cache) => {return cache.addAll(STATIC_FILES);
        })
    );
});

self.addEventListener('activate', (event) => {
    console.log('Service Worker activated');
    event.waitUntil(
        caches.keys().then((cacheNames) => {
            return Promise.all(
                cacheNames.map((cacheName) => {
                    if (cacheName !== CACHE_NAME) {
                        return caches.delete(cacheName);
                    }
                })
            );
        })
    );
});

self.addEventListener('fetch', (event) => {
    event.respondWith(
        caches.match(event.request).then((response) => {
            if (response) {
                return response;
            }
            // Иначе выполняем запрос к сети
            return fetch(event.request);
        })
    );
});

self.addEventListener('message', (event) => {
    if (event.data.type === 'getData') {
        event.source.postMessage({ salt, data });
    }
});








