const RPC_REQUEST_PROCEDURE = 'rpc-request';
const socketClusterClient = require('socketcluster-client');

class SCAdapter {
  constructor(options) {
    this.socket = socketClusterClient.create({
      protocolVersion: 1,
      path: '/socketcluster/',
      ...options,
      autoConnect: false
    });
    this.chainModuleName = options.chainModuleName || 'ldpos_chain';
  }

  async connect() {
    this.socket.connect();
    let event = await Promise.race([
      this.socket.listener('connect').once(),
      this.socket.listener('connectAbort').once()
    ]);
    if (event.code) {
      throw new Error(
        `Failed to connect because of error ${event.code}: ${event.reason}`
      );
    }
  }

  disconnect() {
    this.socket.disconnect();
  }

  async invokeProcedure(action, data) {
    let result = await this.socket.invoke(RPC_REQUEST_PROCEDURE, {
      type: '/RPCRequest',
      procedure: `${this.chainModuleName}:${action}`,
      data
    });
    if (!result) {
      throw new Error(
        'Peer sent back RPC result in an invalid format - Expected an object with a data property'
      );
    }
    return result.data;
  }

  async getNetworkSymbol() {
    return this.invokeProcedure('getNetworkSymbol');
  }

  async getAccount(walletAddress) {
    return this.invokeProcedure('getAccount', { walletAddress });
  }

  async postTransaction(transaction) {
    return this.invokeProcedure('postTransaction', { transaction });
  }
}

module.exports = SCAdapter;
