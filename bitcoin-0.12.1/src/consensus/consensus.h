// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2015 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_CONSENSUS_CONSENSUS_H
#define BITCOIN_CONSENSUS_CONSENSUS_H
//1M区块
/** The maximum allowed size for a serialized block, in bytes (network rule) */
static const unsigned int MAX_BLOCK_SIZE = 1000000;
//最大签名数
/** The maximum allowed number of signature check operations in a block (network rule) */
static const unsigned int MAX_BLOCK_SIGOPS = MAX_BLOCK_SIZE/50;
/** Coinbase transaction outputs can only be spent after this number of new blocks (network rule) */
//基于coinbase 的交易输出要在 COINBASE_MATURITY 个确认之后才能被认定为可消费的（为了防止分叉造成的孤块可交易）
//https://bitcoin.stackexchange.com/questions/1991/what-is-the-block-maturation-time
static const int COINBASE_MATURITY = 100;

/** Flags for nSequence and nLockTime locks */
enum {
    /* Interpret sequence numbers as relative lock-time constraints. */
    LOCKTIME_VERIFY_SEQUENCE = (1 << 0),

    /* Use GetMedianTimePast() instead of nTime for end point timestamp. */
    LOCKTIME_MEDIAN_TIME_PAST = (1 << 1),
};

#endif // BITCOIN_CONSENSUS_CONSENSUS_H
