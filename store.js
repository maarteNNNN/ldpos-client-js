const util = require('util');
const path = require('path');
const fs = require('fs');
const crypto = require('crypto');
const readFile = util.promisify(fs.readFile);
const writeFile = util.promisify(fs.writeFile);
const unlink = util.promisify(fs.unlink);

const DEFAULT_STORE_DIR_PATH = path.resolve(__dirname, 'data');
const DEFAULT_STORE_FILE_EXTENSION = '';

class Store {
  constructor(options) {
    this.storeDirPath = options.storeDirPath == null ? DEFAULT_STORE_DIR_PATH : options.storeDirPath;
    this.storeFileExtension = options.storeFileExtension == null ? DEFAULT_STORE_FILE_EXTENSION : options.storeFileExtension;
  }

  async saveItem(key, value) {
    let safeKey = encodeURIComponent(key);
    let targetFilePath = path.resolve(this.storeDirPath, `${safeKey}${this.storeFileExtension}`);
    try {
      return await writeFile(targetFilePath, String(value), { encoding: 'utf8', flag: 'w' });
    } catch (error) {
      throw new Error(
        `Failed to save the ${key} item to the file system because of error: ${error.message}`
      );
    }
  }

  async loadItem(key) {
    let safeKey = encodeURIComponent(key);
    let targetFilePath = path.resolve(this.storeDirPath, `${safeKey}${this.storeFileExtension}`);
    try {
      return await readFile(targetFilePath, { encoding: 'utf8' });
    } catch (error) {
      if (error.code === 'ENOENT') {
        return undefined;
      }
      throw new Error(
        `Failed to load the ${key} item from the file system because of error: ${error.message}`
      );
    }
  }

  async deleteItem(key) {
    let safeKey = encodeURIComponent(key);
    let targetFilePath = path.resolve(this.storeDirPath, `${safeKey}${this.storeFileExtension}`);
    try {
      await unlink(targetFilePath);
    } catch (error) {
      if (error.code !== 'ENOENT') {
        throw new Error(
          `Failed to delete the ${key} item from the file system because of error: ${error.message}`
        );
      }
    }
  }
}

module.exports = Store;
