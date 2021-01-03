const bip39 = require('bip39');
const ProperMerkle = require('proper-merkle');

const LEAF_COUNT = 32;
const DEFAULT_FORGING_KEY_INDEX_OFFSET = 2;
const DEFAULT_MULTISIG_KEY_INDEX_OFFSET = 10;
const DEFAULT_SIG_KEY_INDEX_OFFSET = 10;

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
    if (options.forgingKeyIndexOffset == null) {
      this.forgingKeyIndexOffset = DEFAULT_FORGING_KEY_INDEX_OFFSET;
    } else {
      this.forgingKeyIndexOffset = options.forgingKeyIndexOffset;
    }

    let maxForgingKeyOffset = Math.floor(LEAF_COUNT / 2);

    if (this.forgingKeyIndexOffset >= maxForgingKeyOffset) {
      throw new Error(
        `The forgingKeyIndexOffset option must be less than ${maxForgingKeyOffset}`
      );
    }
    if (options.multisigKeyIndexOffset == null) {
      this.multisigKeyIndexOffset = DEFAULT_MULTISIG_KEY_INDEX_OFFSET;
    } else {
      this.multisigKeyIndexOffset = options.multisigKeyIndexOffset;
    }
    if (this.multisigKeyIndexOffset >= maxForgingKeyOffset) {
      throw new Error(
        `The multisigKeyIndexOffset option must be less than ${maxForgingKeyOffset}`
      );
    }
    if (options.sigKeyIndexOffset == null) {
      this.sigKeyIndexOffset = DEFAULT_SIG_KEY_INDEX_OFFSET;
    } else {
      this.sigKeyIndexOffset = options.sigKeyIndexOffset;
    }
    if (this.sigKeyIndexOffset >= maxForgingKeyOffset) {
      throw new Error(
        `The sigKeyIndexOffset option must be less than ${maxForgingKeyOffset}`
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
    this.networkSymbol = await this.getNetworkSymbol();

    this.networkSeed = `${this.networkSymbol}-${this.seed}`;
    this.firstSigTree = this.merkle.generateMSSTreeSync(`${this.networkSeed}-sig`, 0);

    let { publicRootHash } = this.firstSigTree;
    this.walletAddress = `${Buffer.from(publicRootHash, 'base64').toString('hex')}${this.networkSymbol}`;
    let account = await this.getAccount(this.walletAddress);

    this.forgingKeyIndex = account.nextForgingKeyIndex + this.forgingKeyIndexOffset;
    this.multisigKeyIndex = account.nextMultisigKeyIndex + this.multisigKeyIndexOffset;
    this.sigKeyIndex = account.nextSigKeyIndex + this.sigKeyIndexOffset;

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
      throw new Error('Account address not loaded - Client needs to connect first');
    }
    return this.walletAddress;
  }

  prepareTransaction(transaction) {
    let extendedTransaction = {
      ...transaction,
      senderAddress: this.walletAddress,
      sigPublicKey: this.sigTree.publicRootHash,
      nextSigPublicKey: this.nextSigTree.publicRootHash,
      nextSigKeyIndex: this.sigKeyIndex + 1
    };

    let extendedTransactionJSON = JSON.stringify(extendedTransaction);
    extendedTransaction.id = this.sha256(extendedTransactionJSON);

    let extendedTransactionWithIdJSON = JSON.stringify(extendedTransaction);
    let leafIndex = this.computeLeafIndex(this.sigKeyIndex);
    let signature = this.merkle.sign(extendedTransactionWithIdJSON, this.sigTree, leafIndex);

    this.incrementSigKey();

    return {
      ...extendedTransaction,
      signature
    };
  }

  verifyTransactionId(transaction) {
    let { id, signature, signatures, ...transactionWithoutIdAndSignatures } = transaction;
    let transactionJSON = JSON.stringify(transactionWithoutIdAndSignatures);
    let expectedId = this.sha256(transactionJSON);
    return id === expectedId;
  }

  verifyTransaction(transaction) {
    if (!this.verifyTransactionId(transaction)) {
      return false;
    }
    let { signature, signatures, ...transactionWithoutSignatures } = transaction;
    let transactionJSON = JSON.stringify(transactionWithoutSignatures);
    return this.merkle.verify(transactionJSON, signature, transaction.sigPublicKey);
  }

  prepareMultisigTransaction(transaction) {
    let extendedTransaction = {
      ...transaction,
      senderAddress: this.walletAddress
    };

    let extendedTransactionJSON = JSON.stringify(extendedTransaction);
    extendedTransaction.id = this.sha256(extendedTransactionJSON);
    extendedTransaction.signatures = [];

    return extendedTransaction;
  }

  signMultisigTransaction(preparedTransaction) {
    let {
      signature: transactionSignature,
      signatures, ...transactionWithoutSignatures
    } = preparedTransaction;

    let metaPacket = {
      signerAddress: this.walletAddress,
      multisigPublicKey: this.multisigTree.publicRootHash,
      nextMultisigPublicKey: this.nextMultisigTree.publicRootHash,
      nextMultisigKeyIndex: this.multisigKeyIndex + 1
    };

    let signablePacket = [transactionWithoutSignatures, metaPacket];

    let signablePacketJSON = JSON.stringify(signablePacket);
    let leafIndex = this.computeLeafIndex(this.multisigKeyIndex);
    let signature = this.merkle.sign(signablePacketJSON, this.multisigTree, leafIndex);

    this.incrementMultisigKey();

    return {
      ...metaPacket,
      signature
    };
  }

  verifyMultisigTransactionSignature(transaction, signaturePacket) {
    let { signature, signatures, ...transactionWithoutSignatures } = transaction;
    let { signature: transactionSignature, ...metaPacket } = signaturePacket;

    let signablePacket = [transactionWithoutSignatures, metaPacket];

    let signablePacketJSON = JSON.stringify(signablePacket);
    return this.merkle.verify(signablePacketJSON, transactionSignature, metaPacket.multisigPublicKey);
  }

  computeSeedName(type) {
    return `${this.networkSeed}-${type}`;
  }

  makeForgingTree(treeIndex) {
    let seedName = this.computeSeedName('forging');
    this.forgingTree = this.merkle.generateMSSTreeSync(seedName, treeIndex);
    this.nextForgingTree = this.merkle.generateMSSTreeSync(seedName, treeIndex + 1);
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
    let seedName = this.computeSeedName('sig');
    this.sigTree = this.merkle.generateMSSTreeSync(seedName, treeIndex);
    this.nextSigTree = this.merkle.generateMSSTreeSync(seedName, treeIndex);
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
    let seedName = this.computeSeedName('multisig');
    this.multisigTree = this.merkle.generateMSSTreeSync(seedName, treeIndex);
    this.nextMultisigTree = this.merkle.generateMSSTreeSync(seedName, treeIndex + 1);
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
    let extendedBlock = {
      ...block,
      forgerAddress: this.walletAddress,
      forgingPublicKey: this.forgingTree.publicRootHash,
      nextForgingPublicKey: this.nextForgingTree.publicRootHash,
      nextForgingKeyIndex: this.forgingKeyIndex + 1
    };

    let extendedBlockJSON = JSON.stringify(extendedBlock);
    extendedBlock.id = this.sha256(extendedBlockJSON);

    let extendedBlockWithIdJSON = JSON.stringify(extendedBlock);
    let leafIndex = this.computeLeafIndex(this.forgingKeyIndex);
    let signature = this.merkle.sign(extendedBlockWithIdJSON, this.forgingTree, leafIndex);

    this.incrementForgingKey();

    return {
      ...extendedBlock,
      signature
    };
  }

  signBlock(preparedBlock) {
    let { signature, signatures, ...blockWithoutSignatures } = preparedBlock;

    let metaPacket = {
      signerAddress: this.walletAddress,
      forgingPublicKey: this.forgingTree.publicRootHash,
      nextForgingPublicKey: this.nextForgingTree.publicRootHash,
      nextForgingKeyIndex: this.forgingKeyIndex + 1
    };

    let signablePacket = [blockWithoutSignatures, metaPacket];

    let signablePacketJSON = JSON.stringify(signablePacket);
    let leafIndex = this.computeLeafIndex(this.forgingKeyIndex);
    let signature = this.merkle.sign(signablePacketJSON, this.forgingTree, leafIndex);

    this.incrementForgingKey();

    return {
      ...metaPacket,
      signature
    };
  }

  verifyBlockSignature(preparedBlock, signaturePacket) {
    let { signature, signatures, ...blockWithoutSignatures } = preparedBlock;
    let { signature: blockSignature, ...metaPacket } = signaturePacket;

    let signablePacket = [blockWithoutSignatures, metaPacket];

    let signablePacketJSON = JSON.stringify(signablePacket);
    return this.merkle.verify(signablePacketJSON, blockSignature, metaPacket.forgingPublicKey);
  }

  verifyBlockId(block) {
    let { id, signature, signatures, ...blockWithoutIdAndSignatures } = block;
    let blockJSON = JSON.stringify(blockWithoutIdAndSignatures);
    let expectedId = this.sha256(blockJSON);
    return id === expectedId;
  }

  verifyBlock(block) {
    if (!this.verifyBlockId(block)) {
      return false;
    }
    let { signature, signatures, ...blockWithoutSignatures } = block;
    let blockJSON = JSON.stringify(blockWithoutSignatures);
    return this.merkle.verify(blockJSON, block.signature, block.forgingPublicKey);
  }

  computeTree(type, treeIndex) {
    let seedName = this.computeSeedName(type);
    return this.merkle.generateMSSTreeSync(seedName, treeIndex);
  }

  signMessage(message, tree, leafIndex) {
    return this.merkle.sign(message, tree, leafIndex);
  }

  verifyMessage(message, signature, publicRootHash) {
    return this.merkle.verify(message, signature, publicRootHash);
  }
}

async function createClient(options) {
  let ldposClient = new LDPoSClient(options);
  await ldposClient.connect();
  return ldposClient;
}

module.exports = {
  LDPoSClient,
  createClient
};
