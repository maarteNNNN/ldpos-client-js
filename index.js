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

  async connect() {
    this.networkSymbol = await this.getNetworkSymbol();

    this.networkSeed = `${this.networkSymbol}-${this.seed}`;
    this.firstSigTree = this.merkle.generateMSSTreeSync(`${this.networkSeed}-sig`, 0);

    let { publicRootHash } = this.firstSigTree;
    this.walletAddress = `${Buffer.from(publicRootHash, 'base64').toString('hex')}${this.networkSymbol}`;
    let account = await this.getAccount(this.walletAddress);

    this.forgingKeyIndex = account.forgingKeyIndex + this.forgingKeyIndexOffset;
    this.multisigKeyIndex = account.multisigKeyIndex + this.multisigKeyIndexOffset;
    this.sigKeyIndex = account.sigKeyIndex + this.sigKeyIndexOffset;

    this.makeForgingTree(Math.floor(this.forgingKeyIndex / LEAF_COUNT));
    this.makeMultisigTree(Math.floor(this.multisigKeyIndex / LEAF_COUNT));
    this.makeSigTree(Math.floor(this.sigKeyIndex / LEAF_COUNT));
  }

  disconnect() {

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
      sigKeyIndex: this.sigKeyIndex,
      sigPublicKey: this.sigTree.publicRootHash,
      nextSigPublicKey: this.nextSigTree.publicRootHash
    };

    let extendedTransactionJSON = JSON.stringify(extendedTransaction);
    extendedTransaction.id = this.sha256(extendedTransactionJSON);

    let extendedTransactionWithIdJSON = JSON.stringify(extendedTransaction);
    let signature = this.merkle.sign(extendedTransactionWithIdJSON, this.sigTree, this.sigKeyIndex);

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

    return extendedTransaction;
  }

  signMultisigTransaction(preparedTransaction) {
    let {
      signature: transactionSignature,
      signatures, ...transactionWithoutSignatures
    } = preparedTransaction;

    let metaPacket = {
      signerAddress: this.walletAddress,
      multisigKeyIndex: this.multisigKeyIndex,
      multisigPublicKey: this.multisigTree.publicRootHash,
      nextMultisigPublicKey: this.nextMultisigTree.publicRootHash
    };

    let signablePacket = [transactionWithoutSignatures, metaPacket];

    let signablePacketJSON = JSON.stringify(signablePacket);
    let signature = this.merkle.sign(signablePacketJSON, this.multisigTree, this.multisigKeyIndex);

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

  makeForgingTree(treeIndex) {
    let seedName = `${this.networkSeed}-forging`;
    this.forgingTree = this.merkle.generateMSSTreeSync(seedName, treeIndex);
    this.nextForgingTree = this.merkle.generateMSSTreeSync(seedName, treeIndex + 1);
  }

  incrementForgingKey() {
    let currentTreeIndex = Math.floor(this.forgingKeyIndex / LEAF_COUNT);
    this.forgingKeyIndex++;
    let newTreeIndex = Math.floor(this.forgingKeyIndex / LEAF_COUNT);

    if (newTreeIndex !== currentTreeIndex) {
      this.makeForgingTree(newTreeIndex);
    }
  }

  makeSigTree(treeIndex) {
    let seedName = `${this.networkSeed}-sig`;
    this.sigTree = this.merkle.generateMSSTreeSync(seedName, treeIndex);
    this.nextSigTree = this.merkle.generateMSSTreeSync(seedName, treeIndex);
  }

  incrementSigKey() {
    let currentTreeIndex = Math.floor(this.sigKeyIndex / LEAF_COUNT);
    this.sigKeyIndex++;
    let newTreeIndex = Math.floor(this.sigKeyIndex / LEAF_COUNT);

    if (newTreeIndex !== currentTreeIndex) {
      this.makeSigTree(newTreeIndex);
    }
  }

  makeMultisigTree(treeIndex) {
    let seedName = `${this.networkSeed}-multisig`;
    this.multisigTree = this.merkle.generateMSSTreeSync(seedName, treeIndex);
    this.nextMultisigTree = this.merkle.generateMSSTreeSync(seedName, treeIndex + 1);
  }

  incrementMultisigKey() {
    let currentTreeIndex = Math.floor(this.multisigKeyIndex / LEAF_COUNT);
    this.multisigKeyIndex++;
    let newTreeIndex = Math.floor(this.multisigKeyIndex / LEAF_COUNT);

    if (newTreeIndex !== currentTreeIndex) {
      this.makeMultisigTree(newTreeIndex);
    }
  }

  prepareBlock(block) {
    let extendedBlock = {
      ...block,
      forgerAddress: this.walletAddress,
      forgingKeyIndex: this.forgingKeyIndex,
      forgingPublicKey: this.forgingTree.publicRootHash,
      nextForgingPublicKey: this.nextForgingTree.publicRootHash
    };

    let extendedBlockJSON = JSON.stringify(extendedBlock);
    extendedBlock.id = this.sha256(extendedBlockJSON);

    let extendedBlockWithIdJSON = JSON.stringify(extendedBlock);
    let signature = this.merkle.sign(extendedBlockWithIdJSON, this.forgingTree, this.forgingKeyIndex);

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
      forgingKeyIndex: this.forgingKeyIndex,
      forgingPublicKey: this.forgingTree.publicRootHash,
      nextForgingPublicKey: this.nextForgingTree.publicRootHash
    };

    let signablePacket = [blockWithoutSignatures, metaPacket];

    let signablePacketJSON = JSON.stringify(signablePacket);
    let signature = this.merkle.sign(signablePacketJSON, this.forgingTree, this.forgingKeyIndex);

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

  signMessage(message) {

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
