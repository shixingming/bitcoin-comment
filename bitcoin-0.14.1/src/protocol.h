// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2016 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef __cplusplus
#error This header can only be compiled as C++.
#endif

#ifndef BITCOIN_PROTOCOL_H
#define BITCOIN_PROTOCOL_H

#include "netaddress.h"
#include "serialize.h"
#include "uint256.h"
#include "version.h"

#include <stdint.h>
#include <string>

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





*/
class CMessageHeader {
public:
    enum {
        MESSAGE_START_SIZE = 4,
        COMMAND_SIZE = 12,
        MESSAGE_SIZE_SIZE = 4,
        CHECKSUM_SIZE = 4,

        MESSAGE_SIZE_OFFSET = MESSAGE_START_SIZE + COMMAND_SIZE,
        CHECKSUM_OFFSET = MESSAGE_SIZE_OFFSET + MESSAGE_SIZE_SIZE,
        HEADER_SIZE = MESSAGE_START_SIZE + COMMAND_SIZE + MESSAGE_SIZE_SIZE +
                      CHECKSUM_SIZE
    };
    typedef unsigned char MessageStartChars[MESSAGE_START_SIZE];

    CMessageHeader(const MessageStartChars &pchMessageStartIn);
    CMessageHeader(const MessageStartChars &pchMessageStartIn,
                   const char *pszCommand, unsigned int nMessageSizeIn);

    std::string GetCommand() const;
    bool IsValid(const MessageStartChars &messageStart) const;

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream &s, Operation ser_action) {
        READWRITE(FLATDATA(pchMessageStart));
        READWRITE(FLATDATA(pchCommand));
        READWRITE(nMessageSize);
        READWRITE(FLATDATA(pchChecksum));
    }

    char pchMessageStart[MESSAGE_START_SIZE];
    char pchCommand[COMMAND_SIZE];
    uint32_t nMessageSize;
    uint8_t pchChecksum[CHECKSUM_SIZE];
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
//该version消息在连接开始时 向接收节点提供有关发送节点的信息。
//直到两位同伴 交换消息，才会接受其他消息。
/*
节点初始化时（类CNode的构造函数），发送获取版本信息的命令。接收到此
命令，回应版本信息，同时把所有警告也反馈回去。!
! 发送端只能发送⼀一次获取版本的命令，重复发送时，回应拒绝命令
（reject）。!
! 源节点的版本号不能⼩小于MIN_PEER_PROTO_VERSION（209），否则也回
应拒绝消息，且断开连接。!
! 连接⾃自⼰己时，将断开连接。接收信息中的随机数与本地主机的随机数
（nLocalHostNonce）相同时，就是在连接⾃自⼰己。!
! 发送版本回应命令，新版本为发送端的版本号与PROTOCOL_VERSION
（70002）中的最⼩小值。!
! 发送命令后，把源节点的地址信息添加到节点的地址管理器中。!
! 最后设置源节点成功连接标记（fSuccessfullyConnected），更新源节点地址
时间。!
! 如果源节点是⺴⽹网络节点（节点的fNetworkNode判断），则每隔20分钟更新节
点的IP地址管理器（CAddrMan）中地址信息（CAddrInfo）的时间（nTime）。
*/
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
 * 
 * 当需要获取inventory时，发送此命令，发送时，需要指定范围。!
 * ! 接收到此命令后，按指定范围获取inventory数据（PushGetBlocks）。!
 * ! 每次最多获取50000个。!
⻚页
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

当发送端发送获取数据命令时（”getdata"），接收端从硬盘读取区块，把类型
为MSG_BLOCK的区块反馈回去。!
! 接收端收到区块命令后，当节点不在导⼊入、重建索引状态时，处理区块
（ProcessBlock）。! !
! 如果是DoS攻击，则向源节点发送拒绝消息（reject）。!
!


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
extern const char *PING;
//如果发送ping 消息时遇到TCP / IP错误（例如连接超时），则发送节点可以假定接收节点已断开连接。ping 消息的回应是pong消息。
/**
 * The pong message replies to a ping message, proving to the pinging node that
 * the ponging node is still alive.
 * @since protocol version 60001 as described by BIP31.
 * @see https://bitcoin.org/en/developer-reference#pong
 */
extern const char *PONG;
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
 * 
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

 * 拒绝消息通知接收节点它之前的一条消息被拒绝。
 * 
 * 
 */
extern const char *REJECT;
/**
 * Indicates that a node prefers to receive new block announcements via a
 * "headers" message rather than an "inv".
 * @since protocol version 70012 as described by BIP130.
 * @see https://bitcoin.org/en/developer-reference#sendheaders
 */
extern const char *SENDHEADERS;
/**
 * The feefilter message tells the receiving peer not to inv us any txs
 * which do not meet the specified min fee rate.
 * @since protocol version 70013 as described by BIP133
 */
extern const char *FEEFILTER;
/**
 * Contains a 1-byte bool and 8-byte LE version number.
 * Indicates that a node is willing to provide blocks via "cmpctblock" messages.
 * May indicate that a node prefers to receive new block announcements via a
 * "cmpctblock" message rather than an "inv", depending on message contents.
 * @since protocol version 70014 as described by BIP 152
 */
extern const char *SENDCMPCT;
/**
 * Contains a CBlockHeaderAndShortTxIDs object - providing a header and
 * list of "short txids".
 * @since protocol version 70014 as described by BIP 152
 */
extern const char *CMPCTBLOCK;
/**
 * Contains a BlockTransactionsRequest
 * Peer should respond with "blocktxn" message.
 * @since protocol version 70014 as described by BIP 152
 */
extern const char *GETBLOCKTXN;
/**
 * Contains a BlockTransactions.
 * Sent in response to a "getblocktxn" message.
 * @since protocol version 70014 as described by BIP 152
 */
extern const char *BLOCKTXN;
};

/* Get a vector of all valid message types (see above) */
const std::vector<std::string> &getAllNetMessageTypes();

/** nServices flags */
enum ServiceFlags : uint64_t {
    // Nothing
    NODE_NONE = 0,
    // NODE_NETWORK means that the node is capable of serving the block chain.
    // It is currently set by all Bitcoin Core nodes, and is unset by SPV
    // clients or other peers that just want network services but don't provide
    // them.
    NODE_NETWORK = (1 << 0),
    // NODE_GETUTXO means the node is capable of responding to the getutxo
    // protocol request. Bitcoin Core does not support this but a patch set
    // called Bitcoin XT does. See BIP 64 for details on how this is
    // implemented.
    NODE_GETUTXO = (1 << 1),
    // NODE_BLOOM means the node is capable and willing to handle bloom-filtered
    // connections. Bitcoin Core nodes used to support this by default, without
    // advertising this bit, but no longer do as of protocol version 70011 (=
    // NO_BLOOM_VERSION)
    NODE_BLOOM = (1 << 2),
    // NODE_XTHIN means the node supports Xtreme Thinblocks. If this is turned
    // off then the node will not service nor make xthin requests.
    NODE_XTHIN = (1 << 4),

    // Bits 24-31 are reserved for temporary experiments. Just pick a bit that
    // isn't getting used, or one not being used much, and notify the
    // bitcoin-development mailing list. Remember that service bits are just
    // unauthenticated advertisements, so your code must be robust against
    // collisions and other cases where nodes may be advertising a service they
    // do not actually support. Other service bits should be allocated via the
    // BIP process.
};

/** A CService with information about it as peer */
class CAddress : public CService {
public:
    CAddress();
    explicit CAddress(CService ipIn, ServiceFlags nServicesIn);

    void Init();

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream &s, Operation ser_action) {
        if (ser_action.ForRead()) Init();
        int nVersion = s.GetVersion();
        if (s.GetType() & SER_DISK) READWRITE(nVersion);
        if ((s.GetType() & SER_DISK) ||
            (nVersion >= CADDR_TIME_VERSION && !(s.GetType() & SER_GETHASH)))
            READWRITE(nTime);
        uint64_t nServicesInt = nServices;
        READWRITE(nServicesInt);
        nServices = (ServiceFlags)nServicesInt;
        READWRITE(*(CService *)this);
    }

    // TODO: make private (improves encapsulation)
public:
    ServiceFlags nServices;

    // disk and network only
    unsigned int nTime;
};

/** getdata message type flags */
const uint32_t MSG_EXT_FLAG = 1 << 29;
const uint32_t MSG_TYPE_MASK = 0xffffffff >> 3;

/** getdata / inv message types.
 * These numbers are defined by the protocol. When adding a new value, be sure
 * to mention it in the respective BIP.
 */
enum GetDataMsg {
    UNDEFINED = 0,
    MSG_TX = 1,
    MSG_BLOCK = 2,
    // The following can only occur in getdata. Invs always use TX or BLOCK.
    //!< Defined in BIP37
    MSG_FILTERED_BLOCK = 3,
    //!< Defined in BIP152
    MSG_CMPCT_BLOCK = 4,

    //!< Extension block
    MSG_EXT_TX = MSG_TX | MSG_EXT_FLAG,
    MSG_EXT_BLOCK = MSG_BLOCK | MSG_EXT_FLAG,
};

/** inv message data */
class CInv {
public:
    CInv();
    CInv(int typeIn, const uint256 &hashIn);

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream &s, Operation ser_action) {
        READWRITE(type);
        READWRITE(hash);
    }

    friend bool operator<(const CInv &a, const CInv &b);

    std::string GetCommand() const;
    std::string ToString() const;

    uint32_t GetKind() const { return type & MSG_TYPE_MASK; }

    bool IsTx() const {
        auto k = GetKind();
        return k == MSG_TX;
    }

    bool IsSomeBlock() const {
        auto k = GetKind();
        return k == MSG_BLOCK || k == MSG_FILTERED_BLOCK ||
               k == MSG_CMPCT_BLOCK;
    }

    // TODO: make private (improves encapsulation)
public:
    int type;
    uint256 hash;
};

#endif // BITCOIN_PROTOCOL_H
