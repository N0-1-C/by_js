// JavaScript实现的文件加密解密库
// 基于Web Crypto API的对称加密方案，支持密钥文件和密码两种方式

class VideoCrypto {
    constructor() {
        this.algorithm = 'AES-GCM';
        this.keyLength = 256; // bits
        this.ivLength = 12; // bytes (96 bits recommended for AES-GCM)
        this.tagLength = 16; // bytes (128 bits authentication tag)
        this.pbkdf2Iterations = 100000; // PBKDF2迭代次数
        this.saltLength = 16; // bytes
    }

    // 从密码派生密钥
    async deriveKeyFromPassword(password, salt) {
        try {
            // 将密码转换为ArrayBuffer
            const encoder = new TextEncoder();
            const passwordBuffer = encoder.encode(password);
            
            // 从密码创建密钥
            const passwordKey = await window.crypto.subtle.importKey(
                'raw',
                passwordBuffer,
                { name: 'PBKDF2' },
                false,
                ['deriveKey']
            );
            
            // 使用PBKDF2从密码派生加密密钥
            const derivedKey = await window.crypto.subtle.deriveKey(
                {
                    name: 'PBKDF2',
                    salt: salt,
                    iterations: this.pbkdf2Iterations,
                    hash: 'SHA-256'
                },
                passwordKey,
                {
                    name: this.algorithm,
                    length: this.keyLength
                },
                false,
                ['encrypt', 'decrypt']
            );
            
            return derivedKey;
        } catch (error) {
            throw new Error('从密码派生密钥失败: ' + error.message);
        }
    }

    // 生成随机盐
    generateSalt() {
        return window.crypto.getRandomValues(new Uint8Array(this.saltLength));
    }

    // 生成加密密钥（保持向后兼容）
    async generateKey() {
        try {
            const key = await window.crypto.subtle.generateKey(
                {
                    name: this.algorithm,
                    length: this.keyLength
                },
                true, // 是否可提取
                ['encrypt', 'decrypt'] // 密钥用途
            );
            
            // 导出密钥为ArrayBuffer格式
            const exportedKey = await window.crypto.subtle.exportKey('raw', key);
            return exportedKey;
        } catch (error) {
            throw new Error('密钥生成失败: ' + error.message);
        }
    }

    // 从ArrayBuffer导入密钥（保持向后兼容）
    async importKey(keyBuffer) {
        try {
            const key = await window.crypto.subtle.importKey(
                'raw',
                keyBuffer,
                { name: this.algorithm },
                false, // 不可提取
                ['encrypt', 'decrypt']
            );
            return key;
        } catch (error) {
            throw new Error('密钥导入失败: ' + error.message);
        }
    }

    // 使用密码加密数据块
    async encryptChunkWithPassword(data, password, salt) {
        try {
            const key = await this.deriveKeyFromPassword(password, salt);
            return await this.encryptChunk(data, key);
        } catch (error) {
            throw new Error('使用密码加密数据块失败: ' + error.message);
        }
    }

    // 使用密钥加密数据块
    async encryptChunk(data, key) {
        try {
            // 生成随机IV
            const iv = window.crypto.getRandomValues(new Uint8Array(this.ivLength));
            
            // 执行加密
            const encrypted = await window.crypto.subtle.encrypt(
                {
                    name: this.algorithm,
                    iv: iv,
                    tagLength: this.tagLength * 8 // 转换为bits
                },
                key,
                data
            );
            
            // 将IV和加密数据合并
            const encryptedArray = new Uint8Array(encrypted);
            const result = new Uint8Array(iv.length + encryptedArray.length);
            result.set(iv, 0);
            result.set(encryptedArray, iv.length);
            
            return result;
        } catch (error) {
            throw new Error('数据块加密失败: ' + error.message);
        }
    }

    // 使用密码解密数据块
    async decryptChunkWithPassword(encryptedDataWithIv, password, salt) {
        try {
            const key = await this.deriveKeyFromPassword(password, salt);
            return await this.decryptChunk(encryptedDataWithIv, key);
        } catch (error) {
            throw new Error('使用密码解密数据块失败: ' + error.message);
        }
    }

    // 使用密钥解密数据块
    async decryptChunk(encryptedDataWithIv, key) {
        try {
            // 分离IV和加密数据
            const iv = encryptedDataWithIv.slice(0, this.ivLength);
            const encryptedData = encryptedDataWithIv.slice(this.ivLength);
            
            // 执行解密
            const decrypted = await window.crypto.subtle.decrypt(
                {
                    name: this.algorithm,
                    iv: iv,
                    tagLength: this.tagLength * 8 // 转换为bits
                },
                key,
                encryptedData
            );
            
            return new Uint8Array(decrypted);
        } catch (error) {
            throw new Error('数据块解密失败: ' + error.message);
        }
    }

    // 使用密码加密整个文件
    async encryptFileWithPassword(file, password) {
        try {
            const salt = this.generateSalt();
            const chunkSize = 64 * 1024; // 64KB分块，与Python版本一致
            
            return new Promise((resolve, reject) => {
                const chunks = [];
                let position = 0;
                
                // 创建一个独立的FileReader实例用于此函数
                const reader = new FileReader();
                
                const processChunk = async () => {
                    if (position >= file.size) {
                        // 所有块处理完成，合并结果，包括盐值
                        const result = this.combineEncryptedChunksWithSalt(chunks, salt);
                        resolve(result);
                        return;
                    }
                    
                    const chunk = file.slice(position, position + chunkSize);
                    
                    reader.onload = async (event) => {
                        try {
                            const data = new Uint8Array(event.target.result);
                            const encryptedChunk = await this.encryptChunkWithPassword(data, password, salt);
                            
                            // 存储加密块大小（4字节）和加密数据
                            const chunkSizeBytes = new Uint8Array(4);
                            new DataView(chunkSizeBytes.buffer).setUint32(0, encryptedChunk.length, false); // 大端序
                            
                            chunks.push({
                                sizeBytes: chunkSizeBytes,
                                data: encryptedChunk
                            });
                            
                            position += chunkSize;
                            
                            // 更新进度（如果需要）
                            const progress = Math.min(100, Math.round((position / file.size) * 100));
                            if (window.updateProgress) {
                                window.updateProgress(progress);
                            }
                            
                            processChunk();
                        } catch (error) {
                            reject(error);
                        }
                    };
                    
                    reader.onerror = () => reject(new Error('文件读取错误: ' + reader.error));
                    reader.readAsArrayBuffer(chunk);
                };
                
                processChunk();
            });
        } catch (error) {
            throw new Error('使用密码加密文件失败: ' + error.message);
        }
    }

    // 使用密钥加密整个文件（保持向后兼容）
    async encryptFile(file, keyBuffer) {
        try {
            const key = await this.importKey(keyBuffer);
            const chunkSize = 64 * 1024; // 64KB分块，与Python版本一致
            
            return new Promise((resolve, reject) => {
                const chunks = [];
                let position = 0;
                
                // 创建一个独立的FileReader实例用于此函数
                const reader = new FileReader();
                
                const processChunk = async () => {
                    if (position >= file.size) {
                        // 所有块处理完成，合并结果
                        const result = this.combineEncryptedChunks(chunks);
                        resolve(result);
                        return;
                    }
                    
                    const chunk = file.slice(position, position + chunkSize);
                    
                    reader.onload = async (event) => {
                        try {
                            const data = new Uint8Array(event.target.result);
                            const encryptedChunk = await this.encryptChunk(data, key);
                            
                            // 存储加密块大小（4字节）和加密数据
                            const chunkSizeBytes = new Uint8Array(4);
                            new DataView(chunkSizeBytes.buffer).setUint32(0, encryptedChunk.length, false); // 大端序
                            
                            chunks.push({
                                sizeBytes: chunkSizeBytes,
                                data: encryptedChunk
                            });
                            
                            position += chunkSize;
                            
                            // 更新进度（如果需要）
                            const progress = Math.min(100, Math.round((position / file.size) * 100));
                            if (window.updateProgress) {
                                window.updateProgress(progress);
                            }
                            
                            processChunk();
                        } catch (error) {
                            reject(error);
                        }
                    };
                    
                    reader.onerror = () => reject(new Error('文件读取错误: ' + reader.error));
                    reader.readAsArrayBuffer(chunk);
                };
                
                processChunk();
            });
        } catch (error) {
            throw new Error('文件加密失败: ' + error.message);
        }
    }

    // 将盐值和加密块合并
    combineEncryptedChunksWithSalt(chunks, salt) {
        // 计算总大小（盐值 + 每个块的大小信息 + 加密数据）
        const saltSize = salt.length;
        const totalSize = saltSize + chunks.reduce((sum, chunk) => 
            sum + chunk.sizeBytes.length + chunk.data.length, 0);
        
        const result = new Uint8Array(totalSize);
        let offset = 0;
        
        // 首先添加盐值
        result.set(salt, offset);
        offset += saltSize;
        
        // 然后添加所有加密块
        for (const chunk of chunks) {
            result.set(chunk.sizeBytes, offset);
            offset += chunk.sizeBytes.length;
            result.set(chunk.data, offset);
            offset += chunk.data.length;
        }
        
        return result;
    }

    // 合并加密块（保持向后兼容）
    combineEncryptedChunks(chunks) {
        const totalSize = chunks.reduce((sum, chunk) => 
            sum + chunk.sizeBytes.length + chunk.data.length, 0);
        
        const result = new Uint8Array(totalSize);
        let offset = 0;
        
        for (const chunk of chunks) {
            result.set(chunk.sizeBytes, offset);
            offset += chunk.sizeBytes.length;
            result.set(chunk.data, offset);
            offset += chunk.data.length;
        }
        
        return result;
    }

    // 使用密码解密整个文件
    async decryptFileWithPassword(encryptedFile, password) {
        try {
            return new Promise((resolve, reject) => {
                const reader = new FileReader();
                
                reader.onload = async (event) => {
                    try {
                        const data = new Uint8Array(event.target.result);
                        const result = await this.decryptFileFromBufferWithPassword(data, password);
                        resolve(result);
                    } catch (error) {
                        reject(error);
                    }
                };
                
                reader.onerror = () => reject(new Error('文件读取错误: ' + reader.error));
                reader.readAsArrayBuffer(encryptedFile);
            });
        } catch (error) {
            throw new Error('使用密码解密文件失败: ' + error.message);
        }
    }

    // 使用密钥解密整个文件（保持向后兼容）
    async decryptFile(encryptedFile, keyBuffer) {
        try {
            const key = await this.importKey(keyBuffer);
            
            return new Promise((resolve, reject) => {
                const reader = new FileReader();
                
                reader.onload = async (event) => {
                    try {
                        const data = new Uint8Array(event.target.result);
                        const result = await this.decryptFileFromBuffer(data, key);
                        resolve(result);
                    } catch (error) {
                        reject(error);
                    }
                };
                
                reader.onerror = () => reject(new Error('文件读取错误: ' + reader.error));
                reader.readAsArrayBuffer(encryptedFile);
            });
        } catch (error) {
            throw new Error('文件解密失败: ' + error.message);
        }
    }

    // 从缓冲区使用密码解密文件
    async decryptFileFromBufferWithPassword(encryptedData, password) {
        try {
            // 首先读取盐值
            if (encryptedData.length < this.saltLength) {
                throw new Error('解密失败: 文件格式错误或文件已损坏（盐值缺失）');
            }
            
            const salt = encryptedData.slice(0, this.saltLength);
            const encryptedDataWithoutSalt = encryptedData.slice(this.saltLength);
            
            // 使用盐值和密码派生密钥
            const key = await this.deriveKeyFromPassword(password, salt);
            
            // 解密剩余数据
            return await this.decryptFileFromBuffer(encryptedDataWithoutSalt, key);
        } catch (error) {
            throw new Error('使用密码解密文件过程中出错: ' + error.message);
        }
    }

    // 从缓冲区使用密钥解密文件（保持向后兼容）
    async decryptFileFromBuffer(encryptedData, key) {
        try {
            const chunks = [];
            let position = 0;
            
            while (position < encryptedData.length) {
                // 读取块大小（4字节）
                if (position + 4 > encryptedData.length) {
                    throw new Error('解密失败: 文件格式错误或文件已损坏');
                }
                
                const chunkSize = new DataView(encryptedData.buffer, encryptedData.byteOffset + position, 4)
                    .getUint32(0, false); // 大端序
                position += 4;
                
                // 读取加密块
                if (position + chunkSize > encryptedData.length) {
                    throw new Error('解密失败: 文件格式错误或文件已损坏');
                }
                
                const encryptedChunk = encryptedData.slice(position, position + chunkSize);
                position += chunkSize;
                
                // 解密块
                const decryptedChunk = await this.decryptChunk(encryptedChunk, key);
                chunks.push(decryptedChunk);
            }
            
            // 合并所有解密块
            const totalSize = chunks.reduce((sum, chunk) => sum + chunk.length, 0);
            const result = new Uint8Array(totalSize);
            let offset = 0;
            
            for (const chunk of chunks) {
                result.set(chunk, offset);
                offset += chunk.length;
            }
            
            return result;
        } catch (error) {
            throw new Error('文件解密过程中出错: ' + error.message);
        }
    }

    // 将ArrayBuffer转换为base64字符串（用于密钥保存）
    arrayBufferToBase64(buffer) {
        const bytes = new Uint8Array(buffer);
        let binary = '';
        for (let i = 0; i < bytes.byteLength; i++) {
            binary += String.fromCharCode(bytes[i]);
        }
        return window.btoa(binary);
    }

    // 将base64字符串转换为ArrayBuffer
    base64ToArrayBuffer(base64) {
        const binaryString = window.atob(base64);
        const bytes = new Uint8Array(binaryString.length);
        for (let i = 0; i < binaryString.length; i++) {
            bytes[i] = binaryString.charCodeAt(i);
        }
        return bytes.buffer;
    }
}

// 导出VideoCrypto类（如果在模块环境中使用）
if (typeof module !== 'undefined' && module.exports) {
    module.exports = VideoCrypto;
}