# zk-group-decryptable

An adaptation of [Semaphore v4](https://github.com/semaphore-protocol/semaphore/tree/feat/semaphore-v4) simplified and using [Foundry](https://getfoundry.sh/) for the contracts while also adding the ability to decrypt proofs using STARK-friendly asymmetric ElGamal encryption as implemented by [Shigoto-dev19](https://github.com/Shigoto-dev19/ec-elgamal-circom)

Get started using the [example app](https://github.com/numtel/semaphore-decryptable-example)!

## Deployed Contracts

Network | Contract
--------|-----------
Holesky | [0x0xBE5aaa6dA0445d4a9989702E0FB8B590039112f1](https://holesky.etherscan.io/address/0xBE5aaa6dA0445d4a9989702E0FB8B590039112f1)

## Installation

> You must have Node.js, Yarn, Foundry, and Circom installed.

```
$ git clone git@github.com:numtel/zk-group-decryptable.git
$ cd zk-group-decryptable
$ yarn

# Configure circuit
$ npx circomkit compile semaphore
$ npx circomkit ptau semaphore
$ npx circomkit setup semaphore
$ npx circomkit instantiate semaphore
$ npx circomkit contract semaphore

# Ready to run tests
$ yarn test

# Configure to deploy
$ cp .env.example .env
$ vim .env
$ yarn deploy:holesky
```

## License

MIT
