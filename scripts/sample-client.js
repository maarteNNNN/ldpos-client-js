const { createClient } = require('../index');
const querystring = require('querystring');
const blockchainNodeIp = process.argv[2];
const blockchainNodePort = process.argv[3] || 7001;

(async () => {

  // Address: 092188ca7934529fc624acf62f2b6ce96c3167424f54aa467428f3d0dcdcc60cldpos
  let client = await createClient({
    passphrase: 'clerk aware give dog reopen peasant duty cheese tobacco trouble gold angle',
    adapterOptions: {
      hostname: blockchainNodeIp,
      port: blockchainNodePort,
      query: querystring.stringify({
        ipAddress: '127.0.0.1',
        wsPort: blockchainNodePort,
        protocolVersion: '1.1',
        nethash: 'da3ed6a45429278bac2666961289ca17ad86595d33b31037615d4b8e8f158bba',
        version: '2.0.0'
      })
    }
  });

  let networkSymbol = await client.getNetworkSymbol();
  console.log('Network symbol:', networkSymbol);

  console.log();
  console.log('--------------');
  console.log('--------------');
  console.log('--------------');
  console.log();

  let account = await client.getAccount('092188ca7934529fc624acf62f2b6ce96c3167424f54aa467428f3d0dcdcc60cldpos');
  console.log('Account:', account);

  console.log();
  console.log('--------------');
  console.log('--------------');
  console.log('--------------');
  console.log();

  let preparedTxn = client.prepareTransaction({
    type: 'transfer',
    recipientAddress: '772e25778a36dc33a7c00115471d270ead1458c170b222e9c63f17da588dd9edldpos',
    amount: `100000000`,
    fee: `10000000`,
    timestamp: 100000,
    message: 'Hello world'
  });
  console.log('Prepared transaction:', preparedTxn);

  console.log();
  console.log('--------------');
  console.log('--------------');
  console.log('--------------');
  console.log();

  let preparedMultisigTxn = client.prepareMultisigTransaction({
    type: 'transfer',
    recipientAddress: '772e25778a36dc33a7c00115471d270ead1458c170b222e9c63f17da588dd9edldpos',
    amount: `100000000`,
    fee: `10000000`,
    timestamp: 100000,
    message: 'Testing...'
  });

  let multisigTxnSignature = client.signMultisigTransaction(preparedMultisigTxn);
  console.log('Multisig transaction signature:', multisigTxnSignature);

})();
