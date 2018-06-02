// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2015 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef __cplusplus
#error This header can only be compiled as C++.
#endif

#ifndef BITCOIN_PROTOCOL_H
#define BITCOIN_PROTOCOL_H

#include "netbase.h"
#include "serialize.h"
#include "uint256.h"
#include "version.h"

#include <stdint.h>
#include <string>

#define MESSAGE_START_SIZE 4

/** Message header.
 * (4) message start.
 * (12) command.
 * (4) size.
 * (4) checksum.
 */

/*





All messages in the network protocol use the same container format, which provides a required multi-field message header and an optional payload. The message header format is:
所有的消息都是用的同样的结构格式
Bytes	Name	    Data Type	Description
4	start string	char[4]	    网络魔数 ;当流状态未知时，用于寻找下一条消息 
12	command name	char[12]	命令   for example: version\0\0\0\0\0. https://bitcoin.org/en/developer-reference#protocol-versions
4	payload size	uint32_t	负载块大小 Number of bytes in payload. The current maximum number of bytes (MAX_SIZE) allowed in the payload by Bitcoin Core is 32 MiB—messages with a payload size larger than this will be dropped or rejected.
4	checksum	    char[4]	    校验 Added in protocol version 209. 

First 4 bytes of SHA256(SHA256(payload)) in internal byte order.

If payload is empty, as in verack and getaddr messages, the checksum is always 0x5df6e0e2 (SHA256(SHA256(<empty string>))).



网络协议版本号70012

*/
class CMessageHeader
{
public:
    typedef unsigned char MessageStartChars[MESSAGE_START_SIZE];

    CMessageHeader(const MessageStartChars& pchMessageStartIn);
    CMessageHeader(const MessageStartChars& pchMessageStartIn, const char* pszCommand, unsigned int nMessageSizeIn);

    std::string GetCommand() const;
    bool IsValid(const MessageStartChars& messageStart) const;

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action, int nType, int nVersion)
    {
        READWRITE(FLATDATA(pchMessageStart));
        READWRITE(FLATDATA(pchCommand));
        READWRITE(nMessageSize);
        READWRITE(nChecksum);
    }

    // TODO: make private (improves encapsulation)
public:
    enum {
        COMMAND_SIZE = 12,
        MESSAGE_SIZE_SIZE = sizeof(int),
        CHECKSUM_SIZE = sizeof(int),

        MESSAGE_SIZE_OFFSET = MESSAGE_START_SIZE + COMMAND_SIZE,
        CHECKSUM_OFFSET = MESSAGE_SIZE_OFFSET + MESSAGE_SIZE_SIZE,
        HEADER_SIZE = MESSAGE_START_SIZE + COMMAND_SIZE + MESSAGE_SIZE_SIZE + CHECKSUM_SIZE
    };
    char pchMessageStart[MESSAGE_START_SIZE];
    char pchCommand[COMMAND_SIZE];
    unsigned int nMessageSize;
    unsigned int nChecksum;
};

/**
 * Bitcoin protocol message types. When adding new message types, don't forget
 * to update allNetMessageTypes in protocol.cpp.
 */
namespace NetMsgType {

/**
 * The version message provides information about the transmitting node to the
 * receiving node at the beginning of a connection.
 * @see https://bitcoin.org/en/developer-reference#version
 */
//该version消息在连接开始时 向接收节点提供有关发送节点的信息。直到两位同伴 交换消息，才会接受其他消息。
extern const char *VERSION;
/**
 * The verack message acknowledges a previously-received version message,
 * informing the connecting node that it can begin to send other messages.
 * @see https://bitcoin.org/en/developer-reference#verack
 */
//version 确认消息
extern const char *VERACK;
/**
 * The addr (IP address) message relays connection information for peers on the
 * network.
 * @see https://bitcoin.org/en/developer-reference#addr
 */
//该getaddr消息请求来自接收 节点的addr消息，最好是接受具有大量其他接收节点的IP地址的消息。
//发送节点可以使用这些IP地址来快速更新其可用节点的数据库，而不是等待来路不明的消息
/*
发送端⽤用这个命令⼲⼴广播地址，接收端收到此命令后把接收到的地址添加到节点
的地址管理器中。
! 发送、接收的地址数量最多1000个。!
! 节点地址管理器中的地址数量超过1000个时，不再添加⽼老版本的地址，即源节
点的版本号⼩小于CADDR_TIME_VERSION（31402）。!
! 如果源节点是⺴⽹网络节点（节点的fNetworkNode判断），则每隔20分钟更新节
点的IP地址管理器（CAddrMan）中地址信息（CAddrInfo）的时间（nTime）。
*/
extern const char *ADDR;
/**
 * The inv message (inventory message) transmits one or more inventories of
 * objects known to the transmitting peer.
 * @see https://bitcoin.org/en/developer-reference#inv
 * 当需要获取inventory时，发送此命令，发送时，需要指定范围。
 * 接收到此命令后，按指定范围获取inventory数据（PushGetBlocks）。
 * 每次最多获取50000个。
 */
extern const char *INV;
/**
 * The getdata message requests one or more data objects from another node.
 * @see https://bitcoin.org/en/developer-reference#getdata
 */
extern const char *GETDATA;
/**
 * The merkleblock message is a reply to a getdata message which requested a
 * block using the inventory type MSG_MERKLEBLOCK.
 * @since protocol version 70001 as described by BIP37.
 * @see https://bitcoin.org/en/developer-reference#merkleblock
 */
extern const char *MERKLEBLOCK;
/**
 * The getblocks message requests an inv message that provides block header
 * hashes starting from a particular point in the block chain.
 * @see https://bitcoin.org/en/developer-reference#getblocks
 */
extern const char *GETBLOCKS;
/**
 * The getheaders message requests a headers message that provides block
 * headers starting from a particular point in the block chain.
 * @since protocol version 31800.
 * @see https://bitcoin.org/en/developer-reference#getheaders
 */
extern const char *GETHEADERS;
/**
 * The tx message transmits a single transaction.
 * @see https://bitcoin.org/en/developer-reference#tx
 */
extern const char *TX;
/**
 * The headers message sends one or more block headers to a node which
 * previously requested certain headers with a getheaders message.
 * @since protocol version 31800.
 * @see https://bitcoin.org/en/developer-reference#headers
 */
extern const char *HEADERS;
/**
 * The block message transmits a single serialized block.
 * @see https://bitcoin.org/en/developer-reference#block
 * 当发送端发送获取数据命令时（”getdata"），接收端从硬盘读取区块，把类型
 * 为MSG_BLOCK的区块反馈回去。
 * 接收端收到区块命令后，当节点不在导⼊入、重建索引状态时，处理区块
 * （ProcessBlock）。
 * 如果是DoS攻击，则向源节点发送拒绝消息（reject）。
 */
extern const char *BLOCK;
/**
 * The getaddr message requests an addr message from the receiving node,
 * preferably one with lots of IP addresses of other receiving nodes.
 * @see https://bitcoin.org/en/developer-reference#getaddr
 */
extern const char *GETADDR;
/**
 * The mempool message requests the TXIDs of transactions that the receiving
 * node has verified as valid but which have not yet appeared in a block.
 * @since protocol version 60002.
 * @see https://bitcoin.org/en/developer-reference#mempool
 */
extern const char *MEMPOOL;
/**
 * The ping message is sent periodically to help confirm that the receiving
 * peer is still connected.
 * @see https://bitcoin.org/en/developer-reference#ping
 */
//如果发送ping 消息时遇到TCP / IP错误（例如连接超时），
//则发送节点可以假定接收节点已断开连接。ping 消息的回应是pong消息。
extern const char *PING;
/**
 * The pong message replies to a ping message, proving to the pinging node that
 * the ponging node is still alive.
 * @since protocol version 60001 as described by BIP31.
 * @see https://bitcoin.org/en/developer-reference#pong
 */
extern const char *PONG;
/**
 * The alert message warns nodes of problems that may affect them or the rest
 * of the network.
 * @since protocol version 311.
 * @see https://bitcoin.org/en/developer-reference#alert
 */
extern const char *ALERT;
/**
 * The notfound message is a reply to a getdata message which requested an
 * object the receiving node does not have available for relay.
 * @ince protocol version 70001.
 * @see https://bitcoin.org/en/developer-reference#notfound
 */
extern const char *NOTFOUND;
/**
 * The filterload message tells the receiving peer to filter all relayed
 * transactions and requested merkle blocks through the provided filter.
 * @since protocol version 70001 as described by BIP37.
 *   Only available with service bit NODE_BLOOM since protocol version
 *   70011 as described by BIP111.
 * @see https://bitcoin.org/en/developer-reference#filterload
 */
extern const char *FILTERLOAD;
/**
 * The filteradd message tells the receiving peer to add a single element to a
 * previously-set bloom filter, such as a new public key.
 * @since protocol version 70001 as described by BIP37.
 *   Only available with service bit NODE_BLOOM since protocol version
 *   70011 as described by BIP111.
 * @see https://bitcoin.org/en/developer-reference#filteradd
 * 添加过滤交易信息到源节点的过滤器中（pfilter），过滤信息最⼤大是520字节
 */
extern const char *FILTERADD;
/**
 * The filterclear message tells the receiving peer to remove a previously-set
 * bloom filter.
 * @since protocol version 70001 as described by BIP37.
 *   Only available with service bit NODE_BLOOM since protocol version
 *   70011 as described by BIP111.
 * @see https://bitcoin.org/en/developer-reference#filterclear
 */
extern const char *FILTERCLEAR;
/**
 * The reject message informs the receiving node that one of its previous
 * messages has been rejected.
 * @since protocol version 70002 as described by BIP61.
 * @see https://bitcoin.org/en/developer-reference#reject
 * 拒绝消息    通知接收节点它之前的一条消息被拒绝。
 */
extern const char *REJECT;
/**
 * Indicates that a node prefers to receive new block announcements via a
 * "headers" message rather than an "inv".
 * @since protocol version 70012 as described by BIP130.
 * @see https://bitcoin.org/en/developer-reference#sendheaders
 */
extern const char *SENDHEADERS;

};

/* Get a vector of all valid message types (see above) */
const std::vector<std::string> &getAllNetMessageTypes();

/** nServices flags */
enum {
    // NODE_NETWORK means that the node is capable of serving the block chain. It is currently
    // set by all Bitcoin Core nodes, and is unset by SPV clients or other peers that just want
    // network services but don't provide them.
    NODE_NETWORK = (1 << 0),
    // NODE_GETUTXO means the node is capable of responding to the getutxo protocol request.
    // Bitcoin Core does not support this but a patch set called Bitcoin XT does.
    // See BIP 64 for details on how this is implemented.
    NODE_GETUTXO = (1 << 1),
    // NODE_BLOOM means the node is capable and willing to handle bloom-filtered connections.
    // Bitcoin Core nodes used to support this by default, without advertising this bit,
    // but no longer do as of protocol version 70011 (= NO_BLOOM_VERSION)
    NODE_BLOOM = (1 << 2),

    // Bits 24-31 are reserved for temporary experiments. Just pick a bit that
    // isn't getting used, or one not being used much, and notify the
    // bitcoin-development mailing list. Remember that service bits are just
    // unauthenticated advertisements, so your code must be robust against
    // collisions and other cases where nodes may be advertising a service they
    // do not actually support. Other service bits should be allocated via the
    // BIP process.
};

/** A CService with information about it as peer */
class CAddress : public CService
{
public:
    CAddress();
    explicit CAddress(CService ipIn, uint64_t nServicesIn = NODE_NETWORK);

    void Init();

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action, int nType, int nVersion)
    {
        if (ser_action.ForRead())
            Init();
        if (nType & SER_DISK)
            READWRITE(nVersion);
        if ((nType & SER_DISK) ||
            (nVersion >= CADDR_TIME_VERSION && !(nType & SER_GETHASH)))
            READWRITE(nTime);
        READWRITE(nServices);
        READWRITE(*(CService*)this);
    }

    // TODO: make private (improves encapsulation)
public:
    uint64_t nServices;

    // disk and network only
    unsigned int nTime;
};

/** inv message data */
class CInv
{
public:
    CInv();
    CInv(int typeIn, const uint256& hashIn);
    CInv(const std::string& strType, const uint256& hashIn);

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action, int nType, int nVersion)
    {
        READWRITE(type);
        READWRITE(hash);
    }

    friend bool operator<(const CInv& a, const CInv& b);

    bool IsKnownType() const;
    const char* GetCommand() const;
    std::string ToString() const;

    // TODO: make private (improves encapsulation)
public:
    int type;
    uint256 hash;
};

enum {
    MSG_TX = 1,
    MSG_BLOCK,
    // Nodes may always request a MSG_FILTERED_BLOCK in a getdata, however,
    // MSG_FILTERED_BLOCK should not appear in any invs except as a part of getdata.
    MSG_FILTERED_BLOCK,
};

#endif // BITCOIN_PROTOCOL_H
