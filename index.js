const bip39 = require('bip39');
const ProperMerkle = require('proper-merkle');

const LEAF_COUNT = 32;

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
  }

  async connect() {
    this.networkSymbol = await this.adapter.getNetworkSymbol();

    this.networkSeed = `${this.networkSymbol}-${this.seed}`;
    this.firstSigTree = this.merkle.generateMSSTreeSync(`${this.networkSeed}-sig`, 0);

    let { publicRootHash } = this.firstSigTree;
    this.accountAddress = `${Buffer.from(publicRootHash, 'base64').toString('hex')}${this.networkSymbol}`;
    let account = await this.adapter.getAccount(this.accountAddress);

    this.forgingKeyIndex = account.forgingKeyIndex;
    this.multisigKeyIndex = account.multisigKeyIndex;
    this.sigKeyIndex = account.sigKeyIndex;

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

  signTransaction(transaction) {

  }

  prepareTransaction(transaction) {

  }

  verifyTransaction(transaction, sigPublicKey) {

  }

  signMultisigTransaction(transaction) {

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

  signBlock(preparedBlock) {
    let { signature, signatures, ...blockWithoutSignatures } = preparedBlock;
    let blockJSON = JSON.stringify(blockWithoutSignatures);
    let signature = this.merkle.sign(blockJSON, this.forgingTree, this.forgingKeyIndex);

    this.incrementForgingKey();

    return signature;
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
}

module.exports = {
  LDPoSClient,
  createClient
};
