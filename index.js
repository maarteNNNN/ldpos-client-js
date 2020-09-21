const crypto = require('crypto');
const bip39 = require('bip39');
const ProperMerkle = require('proper-merkle');

const LEAF_COUNT = 32;

let merkle = new ProperMerkle({
  leafCount: LEAF_COUNT
});

class LPoSClient {
  constructor(options) {
    this.options = options || {};
    if (options.adapter) {
      this.adapter = options.adapter;
    } else {
      // TODO 222: Instantiate SocketCluster client and use it as the default adapter
    }
    this.network = options.network || 'lpos';
    this.passphrase = options.passphrase;

    this.seed = bip39.mnemonicToSeedSync(this.passphrase).toString('hex');
    this.networkSeed = `${this.network}-${this.seed}`;
    this.firstSigTree = merkle.generateMSSTreeSync(`${this.networkSeed}-sig`, 0);

    let { publicRootHash } = this.firstSigTree;
    this.accountAddress = `${Buffer.from(publicRootHash, 'base64').toString('hex')}${this.network}`;
  }

  async connect() {
    let keyIndexes = await this.adapter.getAccountKeyIndexes(this.accountAddress);

    this.candidacyKeyIndex = keyIndexes.candidacyKeyIndex;
    this.votingKeyIndex = keyIndexes.votingKeyIndex;
    this.forgingKeyIndex = keyIndexes.forgingKeyIndex;
    this.multisigKeyIndex = keyIndexes.multisigKeyIndex;
    this.sigKeyIndex = keyIndexes.sigKeyIndex;

    this.candidacyTree = merkle.generateMSSTreeSync(`${this.networkSeed}-candidacy`, Math.floor(this.candidacyKeyIndex / LEAF_COUNT));
    this.votingTree = merkle.generateMSSTreeSync(`${this.networkSeed}-voting`, Math.floor(this.votingKeyIndex / LEAF_COUNT));
    this.forgingTree = merkle.generateMSSTreeSync(`${this.networkSeed}-forging`, Math.floor(this.forgingKeyIndex / LEAF_COUNT));
    this.multisigTree = merkle.generateMSSTreeSync(`${this.networkSeed}-multisig`, Math.floor(this.multisigKeyIndex / LEAF_COUNT));
    this.sigTree = merkle.generateMSSTreeSync(`${this.networkSeed}-sig`, Math.floor(this.sigKeyIndex / LEAF_COUNT));
  }

  getAccountAddress() {
    return this.accountAddress;
  }

  generateCandidacyToken() {
    let randomBuffer = crypto.randomBytes();
    let randomString = randomBuffer.toString('hex');
    return {
      candidateAddress: this.accountAddress,
      candidacyNumber: randomString,
      signature: 'TODO 222'
    };
  }
}

async function createLPoSClient(options) {
  let lposClient = new LPoSClient(options);
  await lposClient.connect();
}

module.exports = {
  LPoSClient,
  createLPoSClient
};
