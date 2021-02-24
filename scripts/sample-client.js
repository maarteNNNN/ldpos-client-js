const { createClient } = require('../index');
const blockchainNodeIp = process.argv[2];
const blockchainNodePort = process.argv[3] || 7001;

(async () => {

  // Address: ldpos313ac2d3d1d081901be0c5ce074d1e81a8a0bf5f
  let client = createClient({
    hostname: blockchainNodeIp,
    port: blockchainNodePort,
    networkSymbol: 'ldpos'
  });

  await client.connect({
    passphrase: 'clerk aware give dog reopen peasant duty cheese tobacco trouble gold angle'
  });

  // let updateResult = await client.syncAllKeyIndexes();
  // let updateResult = await client.syncKeyIndex('forging');
  // console.log('UPDATED KEYS:', updateResult);
  // console.log('FORGING KEY INDEX AFTER SYNC', client.forgingKeyIndex);

  // Recipient address: imitate forum impose muffin purity harvest area mixed renew orient wife eyebrow
  for (let i = 0; i < 1; i++) {
    let preparedTxn = await client.prepareTransaction({
      type: 'transfer',
      recipientAddress: 'ldpos75fbb06210575fd8f7f62e0b9267d4386273fc80',
      amount: `${Math.floor(Math.random() * 1)}000000000`,
      fee: `10000000`,
      timestamp: 100000,
      message: `Test ${i}`
    });
  
    await client.postTransaction(preparedTxn);
    console.log(`Posted transaction #${i}`);
  }

  let voteTxn = await client.prepareTransaction({
    type: 'vote',
    delegateAddress: 'ldpos75fbb06210575fd8f7f62e0b9267d4386273fc80',
    fee: `20000000`,
    timestamp: 200000,
    message: ''
  });
  
  await client.postTransaction(voteTxn);
  
  console.log('Prepared transaction:', preparedTxn);

  let preparedMultisigTxn = await client.prepareMultisigTransaction({
    type: 'transfer',
    recipientAddress: 'ldpos75fbb06210575fd8f7f62e0b9267d4386273fc80',
    amount: `100000000`,
    fee: `10000000`,
    timestamp: 100000,
    message: 'Testing...'
  });
  
  let multisigTxnSignature = await client.signMultisigTransaction(preparedMultisigTxn);
  console.log('Multisig transaction signature:', multisigTxnSignature);

  let accountList = await client.getAccountsByBalance(0, 10, 'desc');
  console.log('Account list:', accountList);

  let transactions = await client.getTransactionsByTimestamp(0, 100);
  console.log('TRANSACTIONS:', transactions);

  let accountVotes = await client.getAccountVotes(client.walletAddress);
  console.log('ACCOUNT VOTES:', accountVotes);

  let block = await client.getBlockAtHeight(2);
  console.log('BLOCK:', block);

  // let accounts = await client.getAccountsByBalance(0, 100);
  // console.log('ACCOUNTS:', accounts);

  // let pendingTxnCount = await client.getPendingTransactionCount();
  // console.log('PENDING TRANSACTION COUNT:', pendingTxnCount);

  let result = await client.getBlocksBetweenHeights(0, 100);
  console.log('RESULT:', result);

})();
