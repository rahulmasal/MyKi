// Myki Extension Background Script
// Relays messages between popup and native messaging host

let nativePort = null;

function connectNative() {
    try {
        nativePort = chrome.runtime.connectNative('com.myki.passwordmanager');
        nativePort.onMessage.addListener((msg) => {
            chrome.runtime.sendMessage({ type: 'native_response', data: msg });
        });
        nativePort.onDisconnect.addListener(() => {
            nativePort = null;
            chrome.runtime.sendMessage({ type: 'native_disconnected' });
        });
    } catch (e) {
        console.error('Native messaging connection failed:', e);
    }
}

function disconnectNative() {
    if (nativePort) {
        nativePort.disconnect();
        nativePort = null;
    }
}

function sendToNative(msg) {
    return new Promise((resolve, reject) => {
        if (!nativePort) {
            reject(new Error('Native host not connected'));
            return;
        }
        const listener = (response) => {
            if (response.type === 'native_response') {
                chrome.runtime.onMessage.removeListener(listener);
                resolve(response.data);
            }
        };
        chrome.runtime.onMessage.addListener(listener);
        nativePort.postMessage(msg);
        setTimeout(() => {
            chrome.runtime.onMessage.removeListener(listener);
            reject(new Error('Native host timeout'));
        }, 10000);
    });
}

// Handle messages from popup
chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
    if (request.type === 'connect_native') {
        connectNative();
        sendResponse({ success: true });
        return false;
    }
    if (request.type === 'disconnect_native') {
        disconnectNative();
        sendResponse({ success: true });
        return false;
    }
    if (request.type === 'native_call') {
        sendToNative(request.payload)
            .then((data) => sendResponse({ success: true, data }))
            .catch((e) => sendResponse({ success: false, error: e.message }));
        return true; // keep channel open for async response
    }
    if (request.type === 'check_native') {
        sendResponse({ connected: nativePort !== null });
        return false;
    }
});

chrome.runtime.onInstalled.addListener(() => {
    console.log('Myki Extension installed');
    // Auto-connect to native host
    connectNative();
});
