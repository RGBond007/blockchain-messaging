class Block {
    constructor(timestamp, sender, recipient, message, previousHash = '') {
        this.timestamp = timestamp;
        this.sender = sender;
        this.recipient = recipient;
        this.message = message;
        this.previousHash = previousHash;
        this.nonce = 0;
        this.hash = this.calculateHash();
    }

    calculateHash() {
        return this.hashCode(
            this.previousHash + 
            this.timestamp + 
            this.sender +
            this.recipient +
            this.message + 
            this.nonce
        ).toString(16);
    }

    hashCode(str) {
        let hash = 0x811c9dc5;
        for (let i = 0; i < str.length; i++) {
            hash ^= str.charCodeAt(i);
            hash += (hash << 1) + (hash << 4) + (hash << 7) + (hash << 8) + (hash << 24);
        }
        return hash >>> 0;
    }

    mineBlock(difficulty) {
        const target = Array(difficulty + 1).join("0");
        while (this.hash.substring(0, difficulty) !== target) {
            this.nonce++;
            this.hash = this.calculateHash();
        }
        return this.hash;
    }
}

class Blockchain {
    constructor() {
        this.chain = [this.createGenesisBlock()];
        this.difficulty = 2;
        this.users = new Map();
        this.loadFromLocalStorage();
    }

    createGenesisBlock() {
        return new Block(Date.now(), "system", "system", "Genesis Block", "0");
    }

    generateKeyPair() {
        const privateKey = Math.random().toString(36).substring(2);
        const publicKey = Math.random().toString(36).substring(2);
        return { privateKey, publicKey };
    }

    registerUser(username, password) {
        if (this.users.has(username)) {
            throw new Error('Username already exists');
        }
        const keys = this.generateKeyPair();
        this.users.set(username, {
            password,
            ...keys,
            messages: []
        });
        this.saveToLocalStorage();
        return keys;
    }

    authenticateUser(username, password) {
        const user = this.users.get(username);
        if (!user || user.password !== password) {
            throw new Error('Invalid credentials');
        }
        return user;
    }

    encryptMessage(message, recipientPublicKey) {
        return message.split('').map(char => 
            String.fromCharCode(char.charCodeAt(0) ^ recipientPublicKey.charCodeAt(0))
        ).join('');
    }

    decryptMessage(encryptedMessage, privateKey) {
        return this.encryptMessage(encryptedMessage, privateKey);
    }

    sendMessage(senderUsername, recipientUsername, message) {
        const sender = this.users.get(senderUsername);
        const recipient = this.users.get(recipientUsername);
        
        if (!sender || !recipient) {
            throw new Error('Invalid sender or recipient');
        }

        const encryptedMessage = this.encryptMessage(message, recipient.publicKey);
        const block = new Block(
            Date.now(),
            senderUsername,
            recipientUsername,
            encryptedMessage,
            this.chain[this.chain.length - 1].hash
        );

        block.mineBlock(this.difficulty);
        this.chain.push(block);
        
        recipient.messages.push({
            from: senderUsername,
            message: encryptedMessage,
            timestamp: block.timestamp
        });

        this.saveToLocalStorage();
        return block;
    }

    getMessages(username, password) {
        const user = this.authenticateUser(username, password);
        return user.messages.map(msg => ({
            from: msg.from,
            message: this.decryptMessage(msg.message, user.privateKey),
            timestamp: msg.timestamp
        }));
    }

    saveToLocalStorage() {
        localStorage.setItem('messageChain', JSON.stringify({
            chain: this.chain,
            users: Array.from(this.users.entries())
        }));
    }

    loadFromLocalStorage() {
        const data = JSON.parse(localStorage.getItem('messageChain'));
        if (data) {
            this.chain = data.chain;
            this.users = new Map(data.users);
        }
    }
}