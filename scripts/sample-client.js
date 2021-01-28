const { createClient } = require('../index');
const blockchainNodeIp = process.argv[2];
const blockchainNodePort = process.argv[3] || 7001;

(async () => {

  // Address: CSGIynk0Up/GJKz2Lyts6WwxZ0JPVKpGdCjz0Nzcxgw=ldpos
  let client = createClient({
    hostname: blockchainNodeIp,
    port: blockchainNodePort,
    inboundPort: 0,
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
  // let account = await client.getAccount('CSGIynk0Up/GJKz2Lyts6WwxZ0JPVKpGdCjz0Nzcxgw=ldpos');
  // console.log('Account:', account);
  //
  // console.log();
  // console.log('--------------');
  // console.log('--------------');
  // console.log('--------------');
  // console.log();

  // for (let i = 0; i < 1; i++) {
  //   let preparedTxn = client.prepareTransaction({
  //     type: 'transfer',
  //     recipientAddress: 'dy4ld4o23DOnwAEVRx0nDq0UWMFwsiLpxj8X2liN2e0=ldpos',
  //     amount: `${Math.floor(Math.random() * 100)}000000000`,
  //     fee: `10000000`,
  //     timestamp: 100000,
  //     message: `Test ${i}`
  //   });
  //
  //   await client.postTransaction(preparedTxn);
  //   console.log(`Posted transaction #${i}`);
  // }

  // ----- START MULTISIG WALLET REGISTRATION -----

  // // Recipient passphrase: genius shoulder into daring armor proof cycle bench patrol paper grant picture
  // let preparedTxn = client.prepareTransaction({
  //   type: 'transfer',
  //   recipientAddress: 'dy4ld4o23DOnwAEVRx0nDq0UWMFwsiLpxj8X2liN2e0=ldpos',
  //   amount: '10000000000',
  //   fee: '10000000',
  //   timestamp: 100000,
  //   message: ''
  // });
  //
  // await client.postTransaction(preparedTxn);
  //
  // // Recipient passphrase: dance control outdoor shoe devote rug cute soft stage flavor sound dial
  // preparedTxn = client.prepareTransaction({
  //   type: 'transfer',
  //   recipientAddress: 'C0VXVkDzHiJt5mGEuhLY38RBzBhNUB0ioc2O93mU7yo=ldpos',
  //   amount: '20000000000',
  //   fee: '10000000',
  //   timestamp: 100000,
  //   message: ''
  // });
  //
  // await client.postTransaction(preparedTxn);


  // let clientB = createClient({
  //   hostname: blockchainNodeIp,
  //   port: blockchainNodePort,
  //   inboundPort: 1,
  //   nethash: 'da3ed6a45429278bac2666961289ca17ad86595d33b31037615d4b8e8f158bba'
  // });
  //
  // // Address: dy4ld4o23DOnwAEVRx0nDq0UWMFwsiLpxj8X2liN2e0=ldpos
  // await clientB.connect({
  //   passphrase: 'genius shoulder into daring armor proof cycle bench patrol paper grant picture'
  // });
  //
  // let preparedTxn = clientB.prepareTransaction({
  //   type: 'transfer',
  //   recipientAddress: 'C0VXVkDzHiJt5mGEuhLY38RBzBhNUB0ioc2O93mU7yo=ldpos',
  //   amount: '10000000',
  //   fee: '10000000',
  //   timestamp: Date.now(),
  //   message: ''
  // });
  //
  // await clientB.postTransaction(preparedTxn);


  // let registerMultsigDetailsTxnB = clientB.prepareRegisterMultisigDetails({
  //   fee: '10000000'
  // });
  //
  // await clientB.postTransaction(registerMultsigDetailsTxnB);
  //
  // let clientC = createClient({
  //   hostname: blockchainNodeIp,
  //   port: blockchainNodePort,
  //   inboundPort: 2,
  //   nethash: 'da3ed6a45429278bac2666961289ca17ad86595d33b31037615d4b8e8f158bba'
  // });
  //
  // // Address: C0VXVkDzHiJt5mGEuhLY38RBzBhNUB0ioc2O93mU7yo=ldpos
  // await clientC.connect({
  //   passphrase: 'dance control outdoor shoe devote rug cute soft stage flavor sound dial'
  // });
  //
  // let registerMultsigDetailsTxnC = clientC.prepareRegisterMultisigDetails({
  //   fee: '10000000'
  // });
  //
  // await clientC.postTransaction(registerMultsigDetailsTxnC);
  //
  // let registerMultisigWalletTxn = client.prepareRegisterMultisigWallet({
  //   fee: '50000000',
  //   memberAddresses: [
  //     'dy4ld4o23DOnwAEVRx0nDq0UWMFwsiLpxj8X2liN2e0=ldpos',
  //     'C0VXVkDzHiJt5mGEuhLY38RBzBhNUB0ioc2O93mU7yo=ldpos'
  //   ],
  //   requiredSignatureCount: 2
  // });
  //
  // await client.postTransaction(registerMultisigWalletTxn);

  // ----- END MULTISIG WALLET REGISTRATION -----

  // let voteTxn = client.prepareTransaction({
  //   type: 'vote',
  //   delegateAddress: 'dy4ld4o23DOnwAEVRx0nDq0UWMFwsiLpxj8X2liN2e0=ldpos',
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
  //   recipientAddress: 'dy4ld4o23DOnwAEVRx0nDq0UWMFwsiLpxj8X2liN2e0=ldpos',
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

  // let transactions = await client.getTransactionsByTimestamp(0, 100);
  // console.log('TRANSACTIONS:', transactions);
  //
  // let accountVotes = await client.getAccountVotes(client.walletAddress);
  // console.log('ACCOUNT VOTES:', accountVotes);

  let accounts = await client.getAccountsByBalance(0, 100);
  console.log('ACCOUNTS:', accounts);

  let pendingTxnCount = await client.getPendingTransactionCount();
  console.log('PENDING TXN COUNT:', pendingTxnCount);

})();
