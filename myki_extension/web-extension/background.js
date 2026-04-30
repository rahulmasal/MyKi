// Background script for Myki Extension
// Handles communication between popup, content scripts, and native app

chrome.runtime.onInstalled.addListener(() => {
  console.log('Myki Extension installed');
});

// Future implementation: Native Messaging to talk to Rust core
// chrome.runtime.connectNative('com.myki.passwordmanager');
