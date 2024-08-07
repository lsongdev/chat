import mqtt from 'https://esm.sh/mqtt';
import { ready } from 'https://lsong.org/scripts/dom.js'

const brokerUrl = 'wss://broker.hivemq.com:8884/mqtt';

let client;
let keypair = {};
let contacts = {};

async function loadData() {
  const savedKeypair = localStorage.getItem('keypair');
  const savedContacts = localStorage.getItem('contacts');

  if (savedKeypair) {
    const parsedKeypair = JSON.parse(savedKeypair);
    keypair.publicKey = parsedKeypair.publicKey;
    keypair.privateKey = await importPrivateKey(parsedKeypair.privateKey);
    document.getElementById('publicKeyInput').value = keypair.publicKey;
    document.getElementById('privateKeyInput').value = parsedKeypair.privateKey; // Display the saved private key
    setCustomKeys();
    subscribeToTopic(keypair.publicKey);
  }

  if (savedContacts) {
    contacts = JSON.parse(savedContacts);
    updateContactList();
  }
}

async function saveData() {
  const exportedPrivateKey = await exportPrivateKey(keypair.privateKey);
  const keypairToSave = {
    publicKey: keypair.publicKey,
    privateKey: exportedPrivateKey
  };
  localStorage.setItem('keypair', JSON.stringify(keypairToSave));
  localStorage.setItem('contacts', JSON.stringify(contacts));
}

async function generateKeyPair() {
  const keyPair = await window.crypto.subtle.generateKey(
    {
      name: "ECDH",
      namedCurve: "P-256"
    },
    true,
    ["deriveKey", "deriveBits"]
  );

  const publicKeyBuffer = await window.crypto.subtle.exportKey("raw", keyPair.publicKey);
  keypair.publicKey = bufferToBase64(publicKeyBuffer);
  keypair.privateKey = keyPair.privateKey;

  document.getElementById('publicKeyInput').value = keypair.publicKey;
  const exportedPrivateKey = await exportPrivateKey(keypair.privateKey);
  document.getElementById('privateKeyInput').value = exportedPrivateKey;

  subscribeToTopic(keypair.publicKey);

  await saveData();
}

async function setCustomKeys() {
  const publicKey = document.getElementById('publicKeyInput').value;
  const privateKey = document.getElementById('privateKeyInput').value;

  if (!publicKey || !privateKey) {
    alert("Please enter both public and private keys.");
    return;
  }
  keypair.publicKey = publicKey;
  keypair.privateKey = await importPrivateKey(privateKey);

  subscribeToTopic(keypair.publicKey);
  await saveData();
}

async function exportPrivateKey(privateKey) {
  const exported = await window.crypto.subtle.exportKey("pkcs8", privateKey);
  return bufferToBase64(exported);
}

async function importPrivateKey(privateKeyBase64) {
  return window.crypto.subtle.importKey(
    "pkcs8",
    base64ToBuffer(privateKeyBase64),
    {
      name: "ECDH",
      namedCurve: "P-256"
    },
    true,
    ["deriveKey", "deriveBits"]
  );
}

function connectToBroker() {
  client = mqtt.connect(brokerUrl);

  client.on('connect', () => {
    console.log('Connected to MQTT broker');
    loadData();
  });

  client.on('message', (topic, message) => {
    handleIncomingMessage(topic, message);
  });
}

function subscribeToTopic(topic) {
  client.subscribe(`/user/${topic}`, (err) => {
    if (!err) {
      console.log(`Subscribed to /user/${topic}`);
    }
  });
}

async function handleIncomingMessage(topic, message) {
  const parsedMessage = JSON.parse(message.toString());
  const decryptedMessage = await decryptMessage(parsedMessage);
  const senderName = Object.keys(contacts).find(name => contacts[name] === parsedMessage.from) || parsedMessage.from.substr(0, 10) + '...';
  displayMessage(senderName, decryptedMessage);
}

function bufferToBase64(buffer) {
  return btoa(String.fromCharCode.apply(null, new Uint8Array(buffer)));
}

function base64ToBuffer(base64) {
  return Uint8Array.from(atob(base64), c => c.charCodeAt(0));
}

function displayMessage(sender, message) {
  const messageElement = document.createElement('p');
  messageElement.textContent = `${sender}: ${message}`;
  document.getElementById('messageContainer').appendChild(messageElement);
}

function updateContactList() {
  const select = document.getElementById('recipientSelect');
  select.innerHTML = '';
  for (const [name, publicKey] of Object.entries(contacts)) {
    const option = document.createElement('option');
    option.value = publicKey;
    option.textContent = name;
    select.appendChild(option);
  }
}

document.getElementById('generateKeys').addEventListener('click', generateKeyPair);
document.getElementById('setKeys').addEventListener('click', setCustomKeys);
document.getElementById('addContact').addEventListener('click', () => {
  const name = document.getElementById('contactName').value;
  const publicKey = document.getElementById('contactPublicKey').value;
  if (name && publicKey) {
    contacts[name] = publicKey;
    saveData();
    updateContactList();
    alert(`Contact added: ${name}`);
    document.getElementById('contactName').value = '';
    document.getElementById('contactPublicKey').value = '';
  }
});
document.getElementById('sendMessage').addEventListener('click', async () => {
  const recipientPublicKey = document.getElementById('recipientSelect').value;
  const message = document.getElementById('messageInput').value;
  if (recipientPublicKey && message) {
    await sendMessage(recipientPublicKey, message);
    document.getElementById('messageInput').value = '';
  }
});

connectToBroker();

async function deriveSharedKey(publicKey) {
  const importedPublicKey = await window.crypto.subtle.importKey(
    "raw",
    base64ToBuffer(publicKey),
    {
      name: "ECDH",
      namedCurve: "P-256"
    },
    true,
    []
  );

  return window.crypto.subtle.deriveKey(
    {
      name: "ECDH",
      public: importedPublicKey
    },
    keypair.privateKey,
    {
      name: "AES-GCM",
      length: 256
    },
    true,
    ["encrypt", "decrypt"]
  );
}

async function sendMessage(recipientPublicKey, message) {
  // Generate a random AES key for this message
  const aesKey = await window.crypto.subtle.generateKey(
    {
      name: "AES-GCM",
      length: 256
    },
    true,
    ["encrypt", "decrypt"]
  );

  // Encrypt the message with the AES key
  const iv = window.crypto.getRandomValues(new Uint8Array(12));
  const encryptedMessage = await window.crypto.subtle.encrypt(
    {
      name: "AES-GCM",
      iv: iv
    },
    aesKey,
    new TextEncoder().encode(message)
  );

  // Use ECDH to create a shared secret
  const sharedKey = await deriveSharedKey(recipientPublicKey, keypair.privateKey);

  // Encrypt the AES key with the shared secret
  const encryptedAesKey = await window.crypto.subtle.encrypt(
    {
      name: "AES-GCM",
      iv: iv
    },
    sharedKey,
    await window.crypto.subtle.exportKey("raw", aesKey)
  );

  const payload = JSON.stringify({
    from: keypair.publicKey,
    iv: bufferToBase64(iv),
    encryptedAesKey: bufferToBase64(encryptedAesKey),
    message: bufferToBase64(encryptedMessage)
  });

  client.publish(`/user/${recipientPublicKey}`, payload);
  displayMessage('You', message);
}

async function decryptMessage(encryptedMessage) {
  // Derive the shared key using ECDH
  const sharedKey = await deriveSharedKey(encryptedMessage.from, keypair.privateKey);

  // Decrypt the AES key
  const aesKeyBuffer = await window.crypto.subtle.decrypt(
    {
      name: "AES-GCM",
      iv: base64ToBuffer(encryptedMessage.iv)
    },
    sharedKey,
    base64ToBuffer(encryptedMessage.encryptedAesKey)
  );

  // Import the decrypted AES key
  const aesKey = await window.crypto.subtle.importKey(
    "raw",
    aesKeyBuffer,
    {
      name: "AES-GCM",
      length: 256
    },
    true,
    ["encrypt", "decrypt"]
  );

  // Decrypt the message using the AES key
  const decrypted = await window.crypto.subtle.decrypt(
    {
      name: "AES-GCM",
      iv: base64ToBuffer(encryptedMessage.iv)
    },
    aesKey,
    base64ToBuffer(encryptedMessage.message)
  );

  return new TextDecoder().decode(decrypted);
}
