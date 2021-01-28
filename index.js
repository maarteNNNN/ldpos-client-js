const bip39 = require('bip39');
const ProperMerkle = require('proper-merkle');
const SCAdapter = require('./sc-adapter');

const LEAF_COUNT = 32;
const DEFAULT_FORGING_KEY_INDEX_OFFSET = 2;
const DEFAULT_MULTISIG_KEY_INDEX_OFFSET = 10;
const DEFAULT_SIG_KEY_INDEX_OFFSET = 3;

// TODO: Add methods for proving or disproving a signed transaction based on signatureHash.

class LDPoSClient {
  constructor(options) {
    this.options = options || {};
    if (options.adapter) {
      this.adapter = options.adapter;
    } else {
      if (
        options.hostname == null ||
        options.port == null ||
        options.nethash == null
      ) {
        throw new Error(
          `If a custom adapter is not specified, then a hostname, port and nethash must be specified`
        );
      }
      this.adapter = new SCAdapter(options);
    }
    this.merkle = new ProperMerkle({
      leafCount: LEAF_COUNT
    });

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

  async connect(options) {
    options = options || {};

    if (options.passphrase) {
      this.passphrase = options.passphrase;
      this.seed = this.computeSeedFromPassphrase(this.passphrase);
    } else {
      throw new Error('Cannot connect client without a passphrase');
    }
    if (options.multisigPassphrase) {
      this.multisigPassphrase = options.multisigPassphrase;
      this.multisigSeed = this.computeSeedFromPassphrase(this.multisigPassphrase);
    } else {
      this.multisigPassphrase = this.passphrase;
      this.multisigSeed = this.seed;
    }
    if (options.forgingPassphrase) {
      this.forgingPassphrase = options.forgingPassphrase;
      this.forgingSeed = this.computeSeedFromPassphrase(this.forgingPassphrase);
    } else {
      this.forgingPassphrase = this.passphrase;
      this.forgingSeed = this.seed;
    }

    if (this.adapter.connect) {
      await this.adapter.connect();
    }
    this.networkSymbol = await this.getNetworkSymbol();

    if (options.walletAddress == null) {
      let treeName = this.computeTreeName('sig', 0);
      let { publicRootHash } = this.merkle.generateMSSTreeSync(this.seed, treeName);
      this.walletAddress = `${publicRootHash}${this.networkSymbol}`;
    } else {
      this.walletAddress = options.walletAddress;
    }

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

  generateWallet() {
    let passphrase = bip39.generateMnemonic();
    let seed = this.computeSeedFromPassphrase(passphrase);
    let sigTreeName = this.computeTreeName('sig', 0);
    let sigTree = this.merkle.generateMSSTreeSync(seed, sigTreeName);
    let walletAddress = `${sigTree.publicRootHash}${this.networkSymbol}`;
    return {
      address: walletAddress,
      passphrase
    };
  }

  validatePassphrase(passphrase) {
    return bip39.validateMnemonic(passphrase);
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

  prepareTransaction(transaction) {
    if (!this.sigTree) {
      throw new Error('Client must be connected with a passphrase in order to prepare a transaction');
    }
    let extendedTransaction = {
      ...transaction,
      senderAddress: this.walletAddress,
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

  prepareRegisterMultisigWallet(options) {
    options = options || {};
    let { memberAddresses, requiredSignatureCount } = options;
    return this.prepareTransaction({
      type: 'registerMultisigWallet',
      fee: options.fee,
      memberAddresses,
      requiredSignatureCount,
      timestamp: options.timestamp == null ? Date.now() : options.timestamp,
      message: options.message == null ? '' : options.message
    });
  }

  prepareRegisterSigDetails(options) {
    options = options || {};
    let sigPassphrase = options.passphrase || this.passphrase;
    let newNextSigKeyIndex = options.newNextSigKeyIndex || 0;
    let treeIndex = this.computeTreeIndex(newNextSigKeyIndex);
    let seed = this.computeSeedFromPassphrase(sigPassphrase);
    let mssTree = this.computeTreeFromSeed(seed, 'sig', treeIndex);
    let nextMSSTree = this.computeTreeFromSeed(seed, 'sig', treeIndex + 1);
    return this.prepareTransaction({
      type: 'registerSigDetails',
      fee: options.fee,
      newSigPublicKey: mssTree.publicRootHash,
      newNextSigPublicKey: nextMSSTree.publicRootHash,
      newNextSigKeyIndex,
      timestamp: options.timestamp == null ? Date.now() : options.timestamp,
      message: options.message == null ? '' : options.message
    });
  }

  prepareRegisterMultisigDetails(options) {
    options = options || {};
    let multisigPassphrase = options.multisigPassphrase || this.multisigPassphrase;
    let newNextMultisigKeyIndex = options.newNextMultisigKeyIndex || 0;
    let treeIndex = this.computeTreeIndex(newNextMultisigKeyIndex);
    let seed = this.computeSeedFromPassphrase(multisigPassphrase);
    let mssTree = this.computeTreeFromSeed(seed, 'multisig', treeIndex);
    let nextMSSTree = this.computeTreeFromSeed(seed, 'multisig', treeIndex + 1);
    return this.prepareTransaction({
      type: 'registerMultisigDetails',
      fee: options.fee,
      newMultisigPublicKey: mssTree.publicRootHash,
      newNextMultisigPublicKey: nextMSSTree.publicRootHash,
      newNextMultisigKeyIndex,
      timestamp: options.timestamp == null ? Date.now() : options.timestamp,
      message: options.message == null ? '' : options.message
    });
  }

  prepareRegisterForgingDetails(options) {
    options = options || {};
    let forgingPassphrase = options.forgingPassphrase || this.forgingPassphrase;
    let newNextForgingKeyIndex = options.newNextForgingKeyIndex || 0;
    let treeIndex = this.computeTreeIndex(newNextForgingKeyIndex);
    let seed = this.computeSeedFromPassphrase(forgingPassphrase);
    let mssTree = this.computeTreeFromSeed(seed, 'forging', treeIndex);
    let nextMSSTree = this.computeTreeFromSeed(seed, 'forging', treeIndex + 1);
    return this.prepareTransaction({
      type: 'registerForgingDetails',
      fee: options.fee,
      newForgingPublicKey: mssTree.publicRootHash,
      newNextForgingPublicKey: nextMSSTree.publicRootHash,
      newNextForgingKeyIndex,
      timestamp: options.timestamp == null ? Date.now() : options.timestamp,
      message: options.message == null ? '' : options.message
    });
  }

  verifyTransactionId(transaction) {
    let { id, senderSignature, senderSignatureHash, signatures, ...transactionWithoutIdAndSignatures } = transaction;
    let transactionJSON = this.stringifyObject(transactionWithoutIdAndSignatures);
    let expectedId = this.sha256(transactionJSON);
    return id === expectedId;
  }

  getAllObjectKeySet(object, seenRefSet) {
    if (!seenRefSet) {
      seenRefSet = new Set();
    }
    let keySet = new Set();
    if (seenRefSet.has(object)) {
      return keySet;
    }
    seenRefSet.add(object);
    if (typeof object !== 'object') {
      return keySet;
    }
    for (let key in object) {
      keySet.add(key);
      let item = object[key];
      let itemKeyList = this.getAllObjectKeySet(item, seenRefSet);
      for (let itemKey of itemKeyList) {
        keySet.add(itemKey);
      }
    }
    return keySet;
  }

  getAllObjectKeys(object) {
    return [...this.getAllObjectKeySet(object)];
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
    if (!this.walletAddress && !transaction.senderAddress) {
      throw new Error(
        'Client must be connected with a passphrase in order to prepare a multisig transaction without a senderAddress'
      );
    }
    let extendedTransaction = {
      ...transaction,
      senderAddress: transaction.senderAddress || this.walletAddress
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
    this.forgingTree = this.merkle.generateMSSTreeSync(this.forgingSeed, treeName);
    let nextTreeName = this.computeTreeName('forging', treeIndex + 1);
    this.nextForgingTree = this.merkle.generateMSSTreeSync(this.forgingSeed, nextTreeName);
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
    this.multisigTree = this.merkle.generateMSSTreeSync(this.multisigSeed, treeName);
    let nextTreeName = this.computeTreeName('multisig', treeIndex + 1);
    this.nextMultisigTree = this.merkle.generateMSSTreeSync(this.multisigSeed, nextTreeName);
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

  computeSeedFromPassphrase(passphrase) {
    return bip39.mnemonicToSeedSync(passphrase).toString('base64');
  }

  computeTreeFromSeed(seed, type, treeIndex) {
    let treeName = this.computeTreeName(type, treeIndex);
    return this.merkle.generateMSSTreeSync(seed, treeName);
  }

  computeTree(type, treeIndex) {
    let seed;
    if (type === 'sig') {
      seed = this.seed;
    } else if (type === 'multisig') {
      seed = this.multisigSeed;
    } else if (type === 'forging') {
      seed = this.forgingSeed;
    } else {
      throw new Error(
        `Tree type ${type} is invalid - It must be either sig, multisig or forging`
      );
    }
    if (!seed) {
      throw new Error(
        `Client must be instantiated with a ${
          type
        } passphrase in order to compute an MSS tree of that type`
      );
    }
    return this.computeTreeFromSeed(seed, type, treeIndex);
  }

  signMessage(message, tree, leafIndex) {
    return this.merkle.sign(message, tree, leafIndex);
  }

  verifyMessage(message, signature, publicRootHash) {
    return this.merkle.verify(message, signature, publicRootHash);
  }

  async getNetworkSymbol() {
    this.verifyAdapterSupportsMethod('getNetworkSymbol');
    return this.adapter.getNetworkSymbol();
  }

  async getAccount(walletAddress) {
    this.verifyAdapterSupportsMethod('getAccount');
    return this.adapter.getAccount(walletAddress);
  }

  async getAccountsByBalance(offset, limit, order) {
    this.verifyAdapterSupportsMethod('getAccountsByBalance');
    return this.adapter.getAccountsByBalance(offset, limit, order);
  }

  async getMultisigWalletMembers(walletAddress) {
    this.verifyAdapterSupportsMethod('getMultisigWalletMembers');
    return this.adapter.getMultisigWalletMembers(walletAddress);
  }

  async getSignedPendingTransaction(transactionId) {
    this.verifyAdapterSupportsMethod('getSignedPendingTransaction');
    return this.adapter.getSignedPendingTransaction(transactionId);
  }

  async getOutboundPendingTransactions(walletAddress, offset, limit) {
    this.verifyAdapterSupportsMethod('getOutboundPendingTransactions');
    return this.adapter.getOutboundPendingTransactions(walletAddress, offset, limit);
  }

  async getPendingTransactionCount() {
    this.verifyAdapterSupportsMethod('getPendingTransactionCount');
    return this.adapter.getPendingTransactionCount();
  }

  async postTransaction(preparedTransaction) {
    this.verifyAdapterSupportsMethod('postTransaction');
    return this.adapter.postTransaction(preparedTransaction);
  }

  async getTransaction(transactionId) {
    this.verifyAdapterSupportsMethod('getTransaction');
    return this.adapter.getTransaction(transactionId);
  }

  async getTransactionsByTimestamp(offset, limit, order) {
    this.verifyAdapterSupportsMethod('getTransactionsByTimestamp');
    return this.adapter.getTransactionsByTimestamp(offset, limit, order);
  }

  async getInboundTransactions(walletAddress, fromTimestamp, limit, order) {
    this.verifyAdapterSupportsMethod('getInboundTransactions');
    return this.adapter.getInboundTransactions(walletAddress, fromTimestamp, limit, order);
  }

  async getOutboundTransactions(walletAddress, fromTimestamp, limit, order) {
    this.verifyAdapterSupportsMethod('getOutboundTransactions');
    return this.adapter.getOutboundTransactions(walletAddress, fromTimestamp, limit, order);
  }

  async getTransactionsFromBlock(blockId, offset, limit) {
    this.verifyAdapterSupportsMethod('getTransactionsFromBlock');
    return this.adapter.getTransactionsFromBlock(blockId, offset, limit);
  }

  async getInboundTransactionsFromBlock(walletAddress, blockId) {
    this.verifyAdapterSupportsMethod('getInboundTransactionsFromBlock');
    return this.adapter.getInboundTransactionsFromBlock(walletAddress, blockId);
  }

  async getOutboundTransactionsFromBlock(walletAddress, blockId) {
    this.verifyAdapterSupportsMethod('getOutboundTransactionsFromBlock');
    return this.adapter.getOutboundTransactionsFromBlock(walletAddress, blockId);
  }

  async getLastBlockAtTimestamp(timestamp) {
    this.verifyAdapterSupportsMethod('getLastBlockAtTimestamp');
    return this.adapter.getLastBlockAtTimestamp(timestamp);
  }

  async getMaxBlockHeight() {
    this.verifyAdapterSupportsMethod('getMaxBlockHeight');
    return this.adapter.getMaxBlockHeight();
  }

  async getBlocksFromHeight(height, limit) {
    this.verifyAdapterSupportsMethod('getBlocksFromHeight');
    return this.adapter.getBlocksFromHeight(height, limit);
  }

  async getSignedBlocksFromHeight(height, limit) {
    this.verifyAdapterSupportsMethod('getSignedBlocksFromHeight');
    return this.adapter.getSignedBlocksFromHeight(height, limit);
  }

  async getBlocksBetweenHeights(fromHeight, toHeight, limit) {
    this.verifyAdapterSupportsMethod('getBlocksBetweenHeights');
    return this.adapter.getBlocksBetweenHeights(fromHeight, toHeight, limit);
  }

  async getBlockAtHeight(height) {
    this.verifyAdapterSupportsMethod('getBlockAtHeight');
    return this.adapter.getBlockAtHeight(height);
  }

  async getBlock(blockId) {
    this.verifyAdapterSupportsMethod('getBlock');
    return this.adapter.getBlock(blockId);
  }

  async getBlocksByTimestamp(offset, limit, order) {
    this.verifyAdapterSupportsMethod('getBlocksByTimestamp');
    return this.adapter.getBlocksByTimestamp(offset, limit, order);
  }

  async getDelegatesByVoteWeight(offset, limit, order) {
    this.verifyAdapterSupportsMethod('getDelegatesByVoteWeight');
    return this.adapter.getDelegatesByVoteWeight(offset, limit, order);
  }

  async getForgingDelegates() {
    this.verifyAdapterSupportsMethod('getForgingDelegates');
    return this.adapter.getForgingDelegates();
  }

  async getAccountVotes(walletAddress) {
    this.verifyAdapterSupportsMethod('getAccountVotes');
    return this.adapter.getAccountVotes(walletAddress);
  }

  verifyAdapterSupportsMethod(methodName) {
    if (!this.adapter[methodName]) {
      throw new Error(
        `Client adapter does not support the ${methodName} method`
      );
    }
  }
}

function createClient(options) {
  return new LDPoSClient(options);
}

module.exports = {
  LDPoSClient,
  createClient
};
