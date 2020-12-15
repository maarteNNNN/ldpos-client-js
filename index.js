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
    if (this.forgingKeyIndexOffset >= LEAF_COUNT) {
      throw new Error(
        `The forgingKeyIndexOffset option must be less than the LEAF_COUNT of ${LEAF_COUNT}`
      );
    }
    if (options.multisigKeyIndexOffset == null) {
      this.multisigKeyIndexOffset = DEFAULT_MULTISIG_KEY_INDEX_OFFSET;
    } else {
      this.multisigKeyIndexOffset = options.multisigKeyIndexOffset;
    }
    if (this.multisigKeyIndexOffset >= LEAF_COUNT) {
      throw new Error(
        `The multisigKeyIndexOffset option must be less than the LEAF_COUNT of ${LEAF_COUNT}`
      );
    }
    if (options.sigKeyIndexOffset == null) {
      this.sigKeyIndexOffset = DEFAULT_SIG_KEY_INDEX_OFFSET;
    } else {
      this.sigKeyIndexOffset = options.sigKeyIndexOffset;
    }
    if (this.sigKeyIndexOffset >= LEAF_COUNT) {
      throw new Error(
        `The sigKeyIndexOffset option must be less than the LEAF_COUNT of ${LEAF_COUNT}`
      );
    }
  }

  async connect() {
    this.networkSymbol = await this.adapter.getNetworkSymbol();

    this.networkSeed = `${this.networkSymbol}-${this.seed}`;
    this.firstSigTree = this.merkle.generateMSSTreeSync(`${this.networkSeed}-sig`, 0);

    let { publicRootHash } = this.firstSigTree;
    this.accountAddress = `${Buffer.from(publicRootHash, 'base64').toString('hex')}${this.networkSymbol}`;
    let account = await this.adapter.getAccount(this.accountAddress);

    this.forgingKeyIndex = account.forgingKeyIndex + this.forgingKeyIndexOffset;
    this.multisigKeyIndex = account.multisigKeyIndex + this.multisigKeyIndexOffset;
    this.sigKeyIndex = account.sigKeyIndex + this.sigKeyIndexOffset;

    this.makeForgingTree(Math.floor(this.forgingKeyIndex / LEAF_COUNT));
    this.makeMultisigTree(Math.floor(this.multisigKeyIndex / LEAF_COUNT));
    this.makeSigTree(Math.floor(this.sigKeyIndex / LEAF_COUNT));
  }

  sha256(message) {
    return this.merkle.lamport.hash(message);
  }

  getAccountAddress() {
    if (!this.accountAddress) {
      throw new Error('Account address not loaded - Client needs to connect to a node first');
    }
    return this.accountAddress;
  }

  prepareTransaction(transaction) {
    let extendedTransaction = {
      ...transaction,
      senderAddress: this.accountAddress,
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

  verifyTransaction(transaction, sigPublicKey) {
    // TODO 222: Verify the transaction id as well
  }

  prepareMultisigTransaction(transaction) {
    let extendedTransaction = {
      ...transaction,
      senderAddress: this.accountAddress
    };

    let extendedTransactionJSON = JSON.stringify(extendedTransaction);
    extendedTransaction.id = this.sha256(extendedTransactionJSON);

    return extendedTransaction;
  }

  signMultisigTransaction(preparedTransaction, includeTransactionId) {
    let { signature, signatures, ...transactionWithoutSignatures } = preparedTransaction;
    let transactionJSON = JSON.stringify(transactionWithoutSignatures);
    let signature = this.merkle.sign(transactionJSON, this.multisigTree, this.multisigKeyIndex);

    this.incrementMultisigKey();

    let signaturePacket = {
      signerAddress: this.accountAddress,
      multisigPublicKey: this.multisigTree.publicRootHash,
      nextMultisigPublicKey: this.nextMultisigTree.publicRootHash,
      signature
    };
    if (includeTransactionId) {
      return {
        ...signaturePacket,
        transactionId: preparedTransaction.id
      };
    }
    return signaturePacket;
  }

  verifyMultisigTransactionSignature(transaction, multisigPublicKey, signature) {

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
      forgerAddress: this.accountAddress,
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

  signBlock(preparedBlock, includeBlockId) {
    let { signature, signatures, ...blockWithoutSignatures } = preparedBlock;
    let blockJSON = JSON.stringify(blockWithoutSignatures);
    let signature = this.merkle.sign(blockJSON, this.forgingTree, this.forgingKeyIndex);

    this.incrementForgingKey();

    let signaturePacket = {
      signerAddress: this.accountAddress,
      forgingPublicKey: this.forgingTree.publicRootHash,
      nextForgingPublicKey: this.nextForgingTree.publicRootHash,
      signature
    };

    if (includeBlockId) {
      return {
        ...signaturePacket,
        blockId: preparedBlock.id
      };
    }

    return signaturePacket;
  }

  verifyBlockSignature(preparedBlock, blockSignature, forgingPublicKey) {
    let { signature, signatures, ...blockWithoutSignatures } = preparedBlock;
    let blockJSON = JSON.stringify(blockWithoutSignatures);
    return this.merkle.verify(blockJSON, blockSignature, forgingPublicKey);
  }

  verifyBlockId(block) {
    let { id, signature, signatures, ...blockWithoutIdAndSignatures } = block;
    let blockJSON = JSON.stringify(blockWithoutIdAndSignatures);
    let expectedId = this.sha256(blockJSON);
    return id === expectedId;
  }

  verifyPreviousBlockId(block, previousBlockId) {
    return block.previousBlockId === previousBlockId;
  }

  verifyBlock(block, forgingPublicKey, previousBlockId) {
    if (!block) {
      return false;
    }
    if (!this.verifyBlockId(block)) {
      return false;
    }
    if (!this.verifyPreviousBlockId(block, previousBlockId)) {
      return false;
    }
    return this.verifyBlockSignature(block, block.signature, forgingPublicKey);
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
