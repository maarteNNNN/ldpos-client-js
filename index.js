const bip39 = require('bip39');
const ProperMerkle = require('proper-merkle');

const LEAF_COUNT = 32;
const DEFAULT_FORGING_KEY_INDEX_OFFSET = 2;
const DEFAULT_MULTISIG_KEY_INDEX_OFFSET = 10;
const DEFAULT_SIG_KEY_INDEX_OFFSET = 3;

class LDPoSClient {
  constructor(options) {
    this.options = options || {};
    if (options.adapter) {
      this.adapter = options.adapter;
    } else {
      // TODO 222: Instantiate SocketCluster client and use it as the default adapter
    }
    this.merkle = new ProperMerkle({
      leafCount: LEAF_COUNT
    });
    if (options.passphrase) {
      this.passphrase = options.passphrase;
      this.seed = bip39.mnemonicToSeedSync(this.passphrase).toString('hex');
    }
    let maxKeyOffset = Math.floor(LEAF_COUNT / 2);

    if (options.forgingKeyIndexOffset == null) {
      this.forgingKeyIndexOffset = DEFAULT_FORGING_KEY_INDEX_OFFSET;
    } else {
      this.forgingKeyIndexOffset = options.forgingKeyIndexOffset;
    }
    if (this.forgingKeyIndexOffset >= maxKeyOffset) {
      throw new Error(
        `The forgingKeyIndexOffset option must be less than ${maxKeyOffset}`
      );
    }
    if (options.multisigKeyIndexOffset == null) {
      this.multisigKeyIndexOffset = DEFAULT_MULTISIG_KEY_INDEX_OFFSET;
    } else {
      this.multisigKeyIndexOffset = options.multisigKeyIndexOffset;
    }
    if (this.multisigKeyIndexOffset >= maxKeyOffset) {
      throw new Error(
        `The multisigKeyIndexOffset option must be less than ${maxKeyOffset}`
      );
    }
    if (options.sigKeyIndexOffset == null) {
      this.sigKeyIndexOffset = DEFAULT_SIG_KEY_INDEX_OFFSET;
    } else {
      this.sigKeyIndexOffset = options.sigKeyIndexOffset;
    }
    if (this.sigKeyIndexOffset >= maxKeyOffset) {
      throw new Error(
        `The sigKeyIndexOffset option must be less than ${maxKeyOffset}`
      );
    }
  }

  computeTreeIndex(keyIndex) {
    return Math.floor(keyIndex / LEAF_COUNT);
  }

  computeLeafIndex(keyIndex) {
    return keyIndex % LEAF_COUNT;
  }

  async connect() {
    if (!this.seed) {
      throw new Error('Cannot connect client without a passphrase');
    }
    this.networkSymbol = await this.getNetworkSymbol();

    let treeName = this.computeTreeName('sig', 0);
    this.firstSigTree = this.merkle.generateMSSTreeSync(this.seed, treeName);

    let { publicRootHash } = this.firstSigTree;
    this.walletAddress = `${Buffer.from(publicRootHash, 'base64').toString('hex')}${this.networkSymbol}`;

    let account = await this.getAccount(this.walletAddress);

    this.forgingKeyIndex = (account.nextForgingKeyIndex || 0) + this.forgingKeyIndexOffset;
    this.multisigKeyIndex = (account.nextMultisigKeyIndex || 0) + this.multisigKeyIndexOffset;
    this.sigKeyIndex = (account.nextSigKeyIndex || 0) + this.sigKeyIndexOffset;

    this.makeForgingTree(this.computeTreeIndex(this.forgingKeyIndex));
    this.makeMultisigTree(this.computeTreeIndex(this.multisigKeyIndex));
    this.makeSigTree(this.computeTreeIndex(this.sigKeyIndex));
  }

  disconnect() {
    if (this.adapter.disconnect) {
      this.adapter.disconnect();
    }
  }

  async getNetworkSymbol() {
    return this.adapter.getNetworkSymbol();
  }

  async getAccount(walletAddress) {
    return this.adapter.getAccount(walletAddress);
  }

  sha256(message) {
    return this.merkle.lamport.hash(message);
  }

  getWalletAddress() {
    if (!this.walletAddress) {
      throw new Error(
        'Client must be connected with a passphrase in order to get the wallet address'
      );
    }
    return this.walletAddress;
  }

  async postTransaction(preparedTransaction) {
    return this.adapter.postTransaction(preparedTransaction);
  }

  prepareTransaction(transaction) {
    if (!this.sigTree) {
      throw new Error('Client must be connected with a passphrase in order to prepare a transaction');
    }
    let extendedTransaction = {
      ...transaction,
      senderAddress: transaction.senderAddress == null ? this.walletAddress : transaction.senderAddress,
      sigPublicKey: this.sigTree.publicRootHash,
      nextSigPublicKey: this.nextSigTree.publicRootHash,
      nextSigKeyIndex: this.sigKeyIndex + 1
    };

    let extendedTransactionJSON = this.stringifyObject(extendedTransaction);
    extendedTransaction.id = this.sha256(extendedTransactionJSON);

    let extendedTransactionWithIdJSON = this.stringifyObject(extendedTransaction);
    let leafIndex = this.computeLeafIndex(this.sigKeyIndex);
    let senderSignature = this.merkle.sign(extendedTransactionWithIdJSON, this.sigTree, leafIndex);

    this.incrementSigKey();

    return {
      ...extendedTransaction,
      senderSignature
    };
  }

  verifyTransactionId(transaction) {
    let { id, senderSignature, senderSignatureHash, signatures, ...transactionWithoutIdAndSignatures } = transaction;
    let transactionJSON = this.stringifyObject(transactionWithoutIdAndSignatures);
    let expectedId = this.sha256(transactionJSON);
    return id === expectedId;
  }

  getAllObjectKeys(object) {
    let keyList = [];
    if (typeof object !== 'object') {
      return keyList;
    }
    for (let key in object) {
      keyList.push(key);
      let item = object[key];
      let itemKeyList = this.getAllObjectKeys(item);
      for (let itemKey of itemKeyList) {
        keyList.push(itemKey);
      }
    }
    return keyList;
  }

  stringifyObject(object) {
    let keyList = this.getAllObjectKeys(object);
    return JSON.stringify(object, keyList.sort());
  }

  stringifyObjectWithMetadata(object, metadata) {
    let objectString = this.stringifyObject(object);
    let metadataString = this.stringifyObject(metadata);
    return `[${objectString},${metadataString}]`;
  }

  verifyTransaction(transaction) {
    if (!this.verifyTransactionId(transaction)) {
      return false;
    }
    let { senderSignature, signatures, ...transactionWithoutSignatures } = transaction;
    let transactionJSON = this.stringifyObject(transactionWithoutSignatures);
    return this.merkle.verify(transactionJSON, senderSignature, transaction.sigPublicKey);
  }

  prepareMultisigTransaction(transaction) {
    if (!this.walletAddress) {
      throw new Error('Client must be connected with a passphrase in order to prepare a multisig transaction');
    }
    let extendedTransaction = {
      ...transaction,
      senderAddress: transaction.senderAddress == null ? this.walletAddress : transaction.senderAddress
    };

    let extendedTransactionJSON = this.stringifyObject(extendedTransaction);
    extendedTransaction.id = this.sha256(extendedTransactionJSON);
    extendedTransaction.signatures = [];

    return extendedTransaction;
  }

  signMultisigTransaction(preparedTransaction) {
    if (!this.multisigTree) {
      throw new Error('Client must be connected with a passphrase in order to sign a multisig transaction');
    }
    let { senderSignature, signatures, ...transactionWithoutSignatures } = preparedTransaction;

    let metaPacket = {
      signerAddress: this.walletAddress,
      multisigPublicKey: this.multisigTree.publicRootHash,
      nextMultisigPublicKey: this.nextMultisigTree.publicRootHash,
      nextMultisigKeyIndex: this.multisigKeyIndex + 1
    };

    let signablePacketJSON = this.stringifyObjectWithMetadata(transactionWithoutSignatures, metaPacket);
    let leafIndex = this.computeLeafIndex(this.multisigKeyIndex);
    let signature = this.merkle.sign(signablePacketJSON, this.multisigTree, leafIndex);

    this.incrementMultisigKey();

    return {
      ...metaPacket,
      signature
    };
  }

  attachMultisigTransactionSignature(preparedTransaction, signaturePacket) {
    preparedTransaction.signatures.push(signaturePacket);
    return preparedTransaction;
  }

  verifyMultisigTransactionSignature(transaction, signaturePacket) {
    let { senderSignature, signatures, ...transactionWithoutSignatures } = transaction;
    let { signature, ...metaPacket } = signaturePacket;

    let signablePacketJSON = this.stringifyObjectWithMetadata(transactionWithoutSignatures, metaPacket);
    return this.merkle.verify(signablePacketJSON, signature, metaPacket.multisigPublicKey);
  }

  getForgingPublicKey() {
    if (!this.forgingTree) {
      return null;
    }
    return this.forgingTree.publicRootHash;
  }

  getNextForgingPublicKey() {
    if (!this.nextForgingTree) {
      return null;
    }
    return this.nextForgingTree.publicRootHash;
  }

  getMultisigPublicKey() {
    if (!this.multisigTree) {
      return null;
    }
    return this.multisigTree.publicRootHash;
  }

  getNextMultisigPublicKey() {
    if (!this.nextMultisigTree) {
      return null;
    }
    return this.nextMultisigTree.publicRootHash;
  }

  getSigPublicKey() {
    if (!this.sigTree) {
      return null;
    }
    return this.sigTree.publicRootHash;
  }

  getNextSigPublicKey() {
    if (!this.nextSigTree) {
      return null;
    }
    return this.nextSigTree.publicRootHash;
  }

  computeTreeName(type, index) {
    return `${this.networkSymbol}-${type}-${index}`;
  }

  makeForgingTree(treeIndex) {
    let treeName = this.computeTreeName('forging', treeIndex);
    this.forgingTree = this.merkle.generateMSSTreeSync(this.seed, treeName);
    let nextTreeName = this.computeTreeName('forging', treeIndex + 1);
    this.nextForgingTree = this.merkle.generateMSSTreeSync(this.seed, nextTreeName);
  }

  incrementForgingKey() {
    let currentTreeIndex = this.computeTreeIndex(this.forgingKeyIndex);
    this.forgingKeyIndex++;
    let newTreeIndex = this.computeTreeIndex(this.forgingKeyIndex);

    if (newTreeIndex !== currentTreeIndex) {
      this.makeForgingTree(newTreeIndex);
    }
  }

  makeSigTree(treeIndex) {
    let treeName = this.computeTreeName('sig', treeIndex);
    this.sigTree = this.merkle.generateMSSTreeSync(this.seed, treeName);
    let nextTreeName = this.computeTreeName('sig', treeIndex + 1);
    this.nextSigTree = this.merkle.generateMSSTreeSync(this.seed, nextTreeName);
  }

  incrementSigKey() {
    let currentTreeIndex = this.computeTreeIndex(this.sigKeyIndex);
    this.sigKeyIndex++;
    let newTreeIndex = this.computeTreeIndex(this.sigKeyIndex);

    if (newTreeIndex !== currentTreeIndex) {
      this.makeSigTree(newTreeIndex);
    }
  }

  makeMultisigTree(treeIndex) {
    let treeName = this.computeTreeName('multisig', treeIndex);
    this.multisigTree = this.merkle.generateMSSTreeSync(this.seed, treeName);
    let nextTreeName = this.computeTreeName('multisig', treeIndex + 1);
    this.nextMultisigTree = this.merkle.generateMSSTreeSync(this.seed, nextTreeName);
  }

  incrementMultisigKey() {
    let currentTreeIndex = this.computeTreeIndex(this.multisigKeyIndex);
    this.multisigKeyIndex++;
    let newTreeIndex = this.computeTreeIndex(this.multisigKeyIndex);

    if (newTreeIndex !== currentTreeIndex) {
      this.makeMultisigTree(newTreeIndex);
    }
  }

  prepareBlock(block) {
    if (!this.forgingTree) {
      throw new Error('Client must be connected with a passphrase in order to prepare a block');
    }
    let extendedBlock = {
      ...block,
      forgerAddress: this.walletAddress,
      forgingPublicKey: this.forgingTree.publicRootHash,
      nextForgingPublicKey: this.nextForgingTree.publicRootHash,
      nextForgingKeyIndex: this.forgingKeyIndex + 1
    };

    let extendedBlockJSON = this.stringifyObject(extendedBlock);
    extendedBlock.id = this.sha256(extendedBlockJSON);

    let extendedBlockWithIdJSON = this.stringifyObject(extendedBlock);
    let leafIndex = this.computeLeafIndex(this.forgingKeyIndex);
    let forgerSignature = this.merkle.sign(extendedBlockWithIdJSON, this.forgingTree, leafIndex);

    this.incrementForgingKey();

    return {
      ...extendedBlock,
      forgerSignature,
      signatures: []
    };
  }

  signBlock(preparedBlock) {
    if (!this.forgingTree) {
      throw new Error('Client must be connected with a passphrase in order to sign a block');
    }
    let { forgerSignature, signatures, ...blockWithoutSignatures } = preparedBlock;

    let metaPacket = {
      blockId: blockWithoutSignatures.id,
      signerAddress: this.walletAddress,
      forgingPublicKey: this.forgingTree.publicRootHash,
      nextForgingPublicKey: this.nextForgingTree.publicRootHash,
      nextForgingKeyIndex: this.forgingKeyIndex + 1
    };

    let signablePacketJSON = this.stringifyObjectWithMetadata(blockWithoutSignatures, metaPacket);
    let leafIndex = this.computeLeafIndex(this.forgingKeyIndex);
    let signature = this.merkle.sign(signablePacketJSON, this.forgingTree, leafIndex);

    this.incrementForgingKey();

    return {
      ...metaPacket,
      signature
    };
  }

  verifyBlockSignature(preparedBlock, signaturePacket) {
    let { forgerSignature, signatures, ...blockWithoutSignatures } = preparedBlock;
    let { signature, ...metaPacket } = signaturePacket;

    let signablePacketJSON = this.stringifyObjectWithMetadata(blockWithoutSignatures, metaPacket);
    return this.merkle.verify(signablePacketJSON, signature, metaPacket.forgingPublicKey);
  }

  verifyBlockId(block) {
    let { id, forgerSignature, signatures, ...blockWithoutIdAndSignatures } = block;
    let blockJSON = this.stringifyObject(blockWithoutIdAndSignatures);
    let expectedId = this.sha256(blockJSON);
    return id === expectedId;
  }

  verifyBlock(block) {
    if (!this.verifyBlockId(block)) {
      return false;
    }
    let { forgerSignature, signatures, ...blockWithoutSignatures } = block;
    let blockJSON = this.stringifyObject(blockWithoutSignatures);
    return this.merkle.verify(blockJSON, block.forgerSignature, block.forgingPublicKey);
  }

  computeTree(type, treeIndex) {
    if (!this.seed) {
      throw new Error('Client must be instantiated with a passphrase in order to compute an MSS tree');
    }
    let treeName = this.computeTreeName(type, treeIndex);
    return this.merkle.generateMSSTreeSync(this.seed, treeName);
  }

  signMessage(message, tree, leafIndex) {
    return this.merkle.sign(message, tree, leafIndex);
  }

  verifyMessage(message, signature, publicRootHash) {
    return this.merkle.verify(message, signature, publicRootHash);
  }
}

async function createClient(options) {
  let { connect, ...clientOptions } = options;
  let ldposClient = new LDPoSClient(clientOptions);
  if (connect === undefined || connect) {
    await ldposClient.connect();
  }
  return ldposClient;
}

module.exports = {
  LDPoSClient,
  createClient
};
