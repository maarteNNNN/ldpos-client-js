const crypto = require('crypto');
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
    this.passphrase = options.passphrase;
    this.seed = bip39.mnemonicToSeedSync(this.passphrase).toString('hex');
  }

  async connect() {
    let [networkSymbol, keyIndexes] = await Promise.all([
      this.adapter.getNetworkSymbol(),
      this.adapter.getAccountKeyIndexes(this.accountAddress),
    ]);

    this.networkSymbol = networkSymbol;

    this.networkSeed = `${this.networkSymbol}-${this.seed}`;
    this.firstSigTree = this.merkle.generateMSSTreeSync(`${this.networkSeed}-sig`, 0);

    let { publicRootHash } = this.firstSigTree;
    this.accountAddress = `${Buffer.from(publicRootHash, 'base64').toString('hex')}${this.networkSymbol}`;

    this.forgingKeyIndex = keyIndexes.forgingKeyIndex;
    this.multisigKeyIndex = keyIndexes.multisigKeyIndex;
    this.sigKeyIndex = keyIndexes.sigKeyIndex;

    this.makeForgingTree(Math.floor(this.forgingKeyIndex / LEAF_COUNT));
    this.makeMultisigTree(Math.floor(this.multisigKeyIndex / LEAF_COUNT));
    this.makeSigTree(Math.floor(this.sigKeyIndex / LEAF_COUNT));
  }

  getAccountAddress() {
    if (!this.accountAddress) {
      throw new Error('Account address not loaded - Client needs to connect to a node first');
    }
    return this.accountAddress;
  }

  signTransactions(transactions) {

  }

  verifyTransactions(transactions, sigPublicKey) {

  }

  signMultisigTransactionsJSON(transactions) {

  }

  signMultisigTransactions(transactions) {

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

  signBlock(block) {
    let extendedBlock = {
      ...block,
      forgingPublicKey: this.forgingTree.publicRootHash,
      nextForgingPublicKey: this.nextForgingTree.publicRootHash
    };
    let blockJSON = JSON.stringify(extendedBlock);
    let signature = this.merkle.sign(blockJSON, this.forgingTree, this.forgingKeyIndex);

    this.incrementForgingKey();

    return {
      ...extendedBlock,
      signature
    };
  }

  verifyBlock(block, forgingPublicKey, previousBlockId) {
    if (!block) {
      return false;
    }
    if (block.previousBlockId !== previousBlockId) {
      return false;
    }
    let {signature, ...blockWithoutSignature} = block;
    let blockJSON = JSON.stringify(blockWithoutSignature);
    return this.merkle.verify(blockJSON, signature, forgingPublicKey);
  }

  signMessage(message) {

  }
}

async function createLDPoSClient(options) {
  let ldposClient = new LDPoSClient(options);
  await ldposClient.connect();
}

module.exports = {
  LDPoSClient,
  createLDPoSClient
};
