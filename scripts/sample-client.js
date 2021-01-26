const { createClient } = require('../index');
const blockchainNodeIp = process.argv[2];
const blockchainNodePort = process.argv[3] || 7001;

(async () => {

  // Address: 092188ca7934529fc624acf62f2b6ce96c3167424f54aa467428f3d0dcdcc60cldpos
  let client = createClient({
    hostname: blockchainNodeIp,
    port: blockchainNodePort,
    nethash: 'da3ed6a45429278bac2666961289ca17ad86595d33b31037615d4b8e8f158bba'
  });

  await client.connect({
    passphrase: 'clerk aware give dog reopen peasant duty cheese tobacco trouble gold angle'
  });

  // let networkSymbol = await client.getNetworkSymbol();
  // console.log('Network symbol:', networkSymbol);
  //
  // console.log();
  // console.log('--------------');
  // console.log('--------------');
  // console.log('--------------');
  // console.log();
  //
  // let account = await client.getAccount('092188ca7934529fc624acf62f2b6ce96c3167424f54aa467428f3d0dcdcc60cldpos');
  // console.log('Account:', account);
  //
  // console.log();
  // console.log('--------------');
  // console.log('--------------');
  // console.log('--------------');
  // console.log();

  for (let i = 0; i < 1; i++) {
    let preparedTxn = client.prepareTransaction({
      type: 'transfer',
      recipientAddress: '772e25778a36dc33a7c00115471d270ead1458c170b222e9c63f17da588dd9edldpos',
      amount: `${Math.floor(Math.random() * 100)}000000000`,
      fee: `10000000`,
      timestamp: 100000,
      message: `Test ${i}`
    });

    await client.postTransaction(preparedTxn);
    console.log(`Posted transaction #${i}`);
  }

  // let voteTxn = client.prepareTransaction({
  //   type: 'vote',
  //   delegateAddress: '772e25778a36dc33a7c00115471d270ead1458c170b222e9c63f17da588dd9edldpos',
  //   fee: `20000000`,
  //   timestamp: 200000,
  //   message: ''
  // });
  //
  // await client.postTransaction(voteTxn);

  // console.log('Prepared transaction:', preparedTxn);
  //
  // console.log();
  // console.log('--------------');
  // console.log('--------------');
  // console.log('--------------');
  // console.log();

  // let preparedMultisigTxn = client.prepareMultisigTransaction({
  //   type: 'transfer',
  //   recipientAddress: '772e25778a36dc33a7c00115471d270ead1458c170b222e9c63f17da588dd9edldpos',
  //   amount: `100000000`,
  //   fee: `10000000`,
  //   timestamp: 100000,
  //   message: 'Testing...'
  // });
  //
  // let multisigTxnSignature = client.signMultisigTransaction(preparedMultisigTxn);
  // console.log('Multisig transaction signature:', multisigTxnSignature);
  //
  // console.log();
  // console.log('--------------');
  // console.log('--------------');
  // console.log('--------------');
  // console.log();

  // let accountList = await client.getAccountsByBalance(0, 10, 'desc');
  // console.log('Account list:', accountList);

  let transactions = await client.getTransactionsByTimestamp(0, 100);
  console.log('TRANSACTIONS:', transactions);

  let accountVotes = await client.getAccountVotes(client.walletAddress);
  console.log('ACCOUNT VOTES:', accountVotes);

  let accounts = await client.getAccountsByBalance(0, 100);
  console.log('ACCOUNTS:', accounts);

  let pendingTxnCount = await client.getPendingTransactionCount();
  console.log('PENDING TXN COUNT:', pendingTxnCount);

})();
