const crypto = require('crypto');
const bip39 = require('bip39');
const ProperMerkle = require('proper-merkle');

const LEAF_COUNT = 32;

let merkle = new ProperMerkle({
  leafCount: LEAF_COUNT
});

class LDPoSClient {
  constructor(options) {
    this.options = options || {};
    if (options.adapter) {
      this.adapter = options.adapter;
    } else {
      // TODO 222: Instantiate SocketCluster client and use it as the default adapter
    }
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
    this.firstSigTree = merkle.generateMSSTreeSync(`${this.networkSeed}-sig`, 0);

    let { publicRootHash } = this.firstSigTree;
    this.accountAddress = `${Buffer.from(publicRootHash, 'base64').toString('hex')}${this.networkSymbol}`;

    this.forgingKeyIndex = keyIndexes.forgingKeyIndex;
    this.multisigKeyIndex = keyIndexes.multisigKeyIndex;
    this.sigKeyIndex = keyIndexes.sigKeyIndex;

    this.forgingTree = merkle.generateMSSTreeSync(`${this.networkSeed}-forging`, Math.floor(this.forgingKeyIndex / LEAF_COUNT));
    this.multisigTree = merkle.generateMSSTreeSync(`${this.networkSeed}-multisig`, Math.floor(this.multisigKeyIndex / LEAF_COUNT));
    this.sigTree = merkle.generateMSSTreeSync(`${this.networkSeed}-sig`, Math.floor(this.sigKeyIndex / LEAF_COUNT));
  }

  getAccountAddress() {
    if (!this.accountAddress) {
      throw new Error('Account address not loaded - Client needs to connect to a node first');
    }
    return this.accountAddress;
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
