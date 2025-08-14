const CACHE_NAME = 'biryani-club-v1';
const urlsToCache = [
    '/',
    '/menu',
    '/cart',
    '/login',
    '/register',
    '/static/manifest.json',
    // Bootstrap CSS
    'https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css',
    // Font Awesome
    'https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0/css/all.min.css',
    // Google Fonts
    'https://fonts.googleapis.com/css2?family=Poppins:wght@300;400;500;600;700;800&display=swap',
    // Bootstrap Icons
    'https://cdn.jsdelivr.net/npm/bootstrap-icons@1.10.0/font/bootstrap-icons.css',
    // Bootstrap JS
    'https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/js/bootstrap.bundle.min.js'
];

// Install Service Worker
self.addEventListener('install', function(event) {
    event.waitUntil(
        caches.open(CACHE_NAME)
            .then(function(cache) {
                console.log('Opened cache');
                return cache.addAll(urlsToCache);
            })
    );
});

// Fetch event
self.addEventListener('fetch', function(event) {
    event.respondWith(
        caches.match(event.request)
            .then(function(response) {
                // Return cached version or fetch from network
                if (response) {
                    return response;
                }
                
                // Clone the request because it's a stream
                var fetchRequest = event.request.clone();
                
                return fetch(fetchRequest).then(function(response) {
                    // Check if we received a valid response
                    if (!response || response.status !== 200 || response.type !== 'basic') {
                        return response;
                    }
                    
                    // Clone the response because it's a stream
                    var responseToCache = response.clone();
                    
                    // Cache successful responses
                    caches.open(CACHE_NAME)
                        .then(function(cache) {
                            // Only cache GET requests
                            if (event.request.method === 'GET') {
                                cache.put(event.request, responseToCache);
                            }
                        });
                    
                    return response;
                }).catch(function() {
                    // Return offline page or fallback for failed requests
                    if (event.request.destination === 'document') {
                        return caches.match('/');
                    }
                });
            }
        )
    );
});

// Activate Service Worker
self.addEventListener('activate', function(event) {
    event.waitUntil(
        caches.keys().then(function(cacheNames) {
            return Promise.all(
                cacheNames.map(function(cacheName) {
                    // Delete old caches
                    if (cacheName !== CACHE_NAME) {
                        console.log('Deleting old cache:', cacheName);
                        return caches.delete(cacheName);
                    }
                })
            );
        })
    );
});

// Background Sync for offline orders
self.addEventListener('sync', function(event) {
    if (event.tag === 'background-sync') {
        console.log('Background sync triggered');
        event.waitUntil(doBackgroundSync());
    }
});

function doBackgroundSync() {
    // Handle offline orders when connection is restored
    return new Promise(function(resolve) {
        // Implementation would sync offline orders
        console.log('Syncing offline data...');
        resolve();
    });
}

// Push notifications for order updates
self.addEventListener('push', function(event) {
    const options = {
        body: 'Your order status has been updated!',
        icon: '/static/icon-192.png',
        badge: '/static/badge-72.png',
        data: {
            url: '/my_orders'
        },
        actions: [
            {
                action: 'view',
                title: 'View Orders',
                icon: '/static/icon-view.png'
            },
            {
                action: 'dismiss',
                title: 'Dismiss'
            }
        ]
    };

    event.waitUntil(
        self.registration.showNotification('Biryani Club', options)
    );
});

// Handle notification clicks
self.addEventListener('notificationclick', function(event) {
    event.notification.close();

    if (event.action === 'view') {
        event.waitUntil(
            clients.openWindow(event.notification.data.url)
        );
    }
});

// Handle message events from the main thread
self.addEventListener('message', function(event) {
    if (event.data && event.data.type === 'SKIP_WAITING') {
        self.skipWaiting();
    }
});

// Periodic background sync for order status updates
self.addEventListener('periodicsync', function(event) {
    if (event.tag === 'order-status-sync') {
        event.waitUntil(syncOrderStatus());
    }
});

function syncOrderStatus() {
    // Sync order status in background
    return fetch('/api/sync_order_status')
        .then(response => response.json())
        .then(data => {
            if (data.updates && data.updates.length > 0) {
                // Show notification for status updates
                return self.registration.showNotification('Order Update', {
                    body: `You have ${data.updates.length} order update(s)`,
                    icon: '/static/icon-192.png',
                    data: { url: '/my_orders' }
                });
            }
        })
        .catch(error => console.log('Background sync failed:', error));
}

// Cache strategies for different types of resources
function getCacheStrategy(request) {
    // API requests - Network first
    if (request.url.includes('/api/')) {
        return networkFirst(request);
    }
    
    // Static assets - Cache first
    if (request.url.includes('/static/') || 
        request.url.includes('bootstrap') || 
        request.url.includes('fontawesome') ||
        request.url.includes('googleapis')) {
        return cacheFirst(request);
    }
    
    // Pages - Network first with cache fallback
    if (request.destination === 'document') {
        return networkFirst(request);
    }
    
    // Default - Network first
    return networkFirst(request);
}

function networkFirst(request) {
    return fetch(request).then(response => {
        if (response.ok) {
            const responseClone = response.clone();
            caches.open(CACHE_NAME).then(cache => {
                cache.put(request, responseClone);
            });
        }
        return response;
    }).catch(() => {
        return caches.match(request);
    });
}

function cacheFirst(request) {
    return caches.match(request).then(response => {
        if (response) {
            return response;
        }
        return fetch(request).then(response => {
            if (response.ok) {
                const responseClone = response.clone();
                caches.open(CACHE_NAME).then(cache => {
                    cache.put(request, responseClone);
                });
            }
            return response;
        });
    });
}
