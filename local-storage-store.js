class LocalStorageStore {
  async saveItem(key, value) {
    localStorage.setItem(key, value);
  }

  async loadItem(key) {
    return localStorage.getItem(key);
  }

  async deleteItem(key) {
    return localStorage.removeItem(key);
  }
}

module.exports = LocalStorageStore;
