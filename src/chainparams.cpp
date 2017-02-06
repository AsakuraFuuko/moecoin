// Copyright (c) 2010 Satoshi Nakamoto
// Copyright (c) 2009-2016 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "chainparams.h"
#include "consensus/merkle.h"

#include "tinyformat.h"
#include "util.h"
#include "utilstrencodings.h"

#include <assert.h>

#include <boost/assign/list_of.hpp>

#include "chainparamsseeds.h"
#include "arith_uint256.h"

//#define FIND_GENESIS

#define GENESIS_MERKLE_ROOT "66db04cf23a36037d836daabd9a9c505184bfde732c44f3274e2cae4b5cba48a"

#define MAINNET_GENESIS_HASH "6b756f8848bfca4978f81d51d81b238fd1eaf36e59fa2318e700977f1f6d543c"
#define MAINNET_GENESIS_NONCE 131005175 // 131005175

#define TESTNET_GENESIS_HASH "6b756f8848bfca4978f81d51d81b238fd1eaf36e59fa2318e700977f1f6d543c"
#define TESTNET_GENESIS_NONCE 131005175 //350000000

#define REGTEST_GENESIS_HASH "19561553866e7bfec9de10f1196ab6b71942aa0771e200ca6e3135688c6cd9e7"
#define REGTEST_GENESIS_NONCE 2 //2

bool CheckProofOfWork2(uint256 hash, unsigned int nBits, const Consensus::Params& params)
{
        bool fNegative;
        bool fOverflow;
        arith_uint256 bnTarget;

        bnTarget.SetCompact(nBits, &fNegative, &fOverflow);

        // Check range
        if (fNegative || bnTarget == 0 || fOverflow || bnTarget > UintToArith256(params.powLimit))
                return error("CheckProofOfWork(): nBits below minimum work");

        // Check proof of work matches claimed amount
        if (UintToArith256(hash) > bnTarget)
                return error("CheckProofOfWork(): hash doesn't match nBits");

        return true;
}

static CBlock CreateGenesisBlock(const char* pszTimestamp, const CScript& genesisOutputScript, uint32_t nTime, uint32_t nNonce, uint32_t nBits, int32_t nVersion, const CAmount& genesisReward, const Consensus::Params& consensus)
{
    CMutableTransaction txNew;
    txNew.nVersion = 1;
    txNew.vin.resize(1);
    txNew.vout.resize(1);
    txNew.vin[0].scriptSig = CScript() << 486604799 << CScriptNum(4) << std::vector<unsigned char>((const unsigned char*)pszTimestamp, (const unsigned char*)pszTimestamp + strlen(pszTimestamp));
    txNew.vout[0].nValue = genesisReward;
    txNew.vout[0].scriptPubKey = genesisOutputScript;

    CBlock genesis;
    genesis.nTime    = nTime;
    genesis.nBits    = nBits;
    genesis.nNonce   = nNonce;
    genesis.nVersion = nVersion;
    genesis.vtx.push_back(MakeTransactionRef(std::move(txNew)));
    genesis.hashPrevBlock.SetNull();
    genesis.hashMerkleRoot = BlockMerkleRoot(genesis);

#ifdef FIND_GENESIS
    while (true)
    {
        genesis.nNonce += 1;
        if(genesis.nNonce % 1000000 == 0)
        {
            std::cout << "nonce: " << genesis.nNonce << std::endl;
        }
        if (CheckProofOfWork2(genesis.GetPoWHash(), nBits, consensus))
        {
            std::cout << "find nonce: " << genesis.nNonce << std::endl;
            std::cout << "find hex: " << genesis.GetHash().GetHex() << std::endl;
            std::cout << "find pow hash: " << genesis.GetPoWHash().GetHex() << std::endl;
            break;
        }
    }
#endif
    return genesis;
}

/**
 * Build the genesis block. Note that the output of its generation
 * transaction cannot be spent since it did not originally exist in the
 * database.
 *
 * CBlock(hash=000000000019d6, ver=1, hashPrevBlock=00000000000000, hashMerkleRoot=4a5e1e, nTime=1231006505, nBits=1d00ffff, nNonce=2083236893, vtx=1)
 *   CTransaction(hash=4a5e1e, ver=1, vin.size=1, vout.size=1, nLockTime=0)
 *     CTxIn(COutPoint(000000, -1), coinbase 04ffff001d0104455468652054696d65732030332f4a616e2f32303039204368616e63656c6c6f72206f6e206272696e6b206f66207365636f6e64206261696c6f757420666f722062616e6b73)
 *     CTxOut(nValue=50.00000000, scriptPubKey=0x5F1DF16B2B704C8A578D0B)
 *   vMerkleTree: 4a5e1e
 */
static CBlock CreateGenesisBlock(uint32_t nTime, uint32_t nNonce, uint32_t nBits, int32_t nVersion, const CAmount& genesisReward, const Consensus::Params& consensus)
{
    const char* pszTimestamp = "Moecoin begin at 02/Feb/2017";
    const CScript genesisOutputScript = CScript() << ParseHex("040184710fa689ad5023690c80f3a49c8f13f8d45b8c857fbcbc8bc4a8e4d3eb4b10f4d4604fa08dce601aaf0f470216fe1b51850b4acf21b179c45070ac7b03a9") << OP_CHECKSIG;
    return CreateGenesisBlock(pszTimestamp, genesisOutputScript, nTime, nNonce, nBits, nVersion, genesisReward, consensus);
}

/**
 * Main network
 */
/**
 * What makes a good checkpoint block?
 * + Is surrounded by blocks with reasonable timestamps
 *   (no blocks before with a timestamp after, none after with
 *    timestamp before)
 * + Contains no strange transactions
 */

class CMainParams : public CChainParams {
public:
    CMainParams() {
        strNetworkID = "main";
        consensus.nSubsidyHalvingInterval = 840000;
//        consensus.BIP34Height = 227931;
//        consensus.BIP34Hash = uint256S("0x000000000000024b89b42a942fe0d9fea3bb44ab7bd1b19115dd6a759c0808b8");
//        consensus.BIP65Height = 388381; // 000000000000000004c2b624ed5d7756c508d90fd0da2c7c679febfa6c4735f0
//        consensus.BIP66Height = 363725; // 00000000000000000379eaa19dce8c9b722d46ae6a57c2f1a988119488b50931
        consensus.powLimit = uint256S("00000000ffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
        consensus.nPowTargetTimespan = 3.5 * 24 * 60 * 60; // 3.5 days
        consensus.nPowTargetSpacing = 2.5 * 60;
        consensus.fPowAllowMinDifficultyBlocks = false;
        consensus.fPowNoRetargeting = false;
        consensus.nRuleChangeActivationThreshold = 6048; // 75% of 8064
        consensus.nMinerConfirmationWindow = 8064; // nPowTargetTimespan / nPowTargetSpacing * 4
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].bit = 28;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nStartTime = 1199145601; // January 1, 2008
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nTimeout = 1230767999; // December 31, 2008

        // Deployment of BIP68, BIP112, and BIP113.
        consensus.vDeployments[Consensus::DEPLOYMENT_CSV].bit = 0;
        consensus.vDeployments[Consensus::DEPLOYMENT_CSV].nStartTime = 1462060800; // May 1st, 2016
        consensus.vDeployments[Consensus::DEPLOYMENT_CSV].nTimeout = 1493596800; // May 1st, 2017

        // Deployment of SegWit (BIP141, BIP143, and BIP147)
        consensus.vDeployments[Consensus::DEPLOYMENT_SEGWIT].bit = 1;
        consensus.vDeployments[Consensus::DEPLOYMENT_SEGWIT].nStartTime = 1479168000; // November 15th, 2016.
        consensus.vDeployments[Consensus::DEPLOYMENT_SEGWIT].nTimeout = 1510704000; // November 15th, 2017.

        // The best chain should have at least this much work.
//        consensus.nMinimumChainWork = uint256S("0x0000000000000000000000000000000000000000002cb971dd56d1c583c20f90");

        // By default assume that the signatures in ancestors of this block are valid.
//        consensus.defaultAssumeValid = uint256S("0x0000000000000000030abc968e1bd635736e880b946085c93152969b9a81a6e2"); //447235

        /**
         * The message start string is designed to be unlikely to occur in normal data.
         * The characters are rarely used upper ASCII, not valid as UTF-8, and produce
         * a large 32-bit integer with any alignment.
         */
        pchMessageStart[0] = 0x4d; //M 4d4f4543
        pchMessageStart[1] = 0x4f; //O
        pchMessageStart[2] = 0x45; //E
        pchMessageStart[3] = 0x43; //C
        nDefaultPort = 2233;
        nPruneAfterHeight = 100000;

        genesis = CreateGenesisBlock(1486016235, MAINNET_GENESIS_NONCE, 0x1d00ffff, 1, 50 * COIN, consensus);
        consensus.hashGenesisBlock = genesis.GetHash();
#ifdef FIND_GENESIS
        std::cout << "hex: " << consensus.hashGenesisBlock.GetHex() << std::endl;
        std::cout << "merkle root: " << genesis.hashMerkleRoot.GetHex() << std::endl;
#else
        assert(consensus.hashGenesisBlock == uint256S(MAINNET_GENESIS_HASH));
        assert(genesis.hashMerkleRoot == uint256S(GENESIS_MERKLE_ROOT));
#endif
        // Note that of those with the service bits flag, most only support a subset of possible options
//        vSeeds.push_back(CDNSSeedData("bitcoin.sipa.be", "seed.bitcoin.sipa.be", true)); // Pieter Wuille, only supports x1, x5, x9, and xd
//        vSeeds.push_back(CDNSSeedData("bluematt.me", "dnsseed.bluematt.me", true)); // Matt Corallo, only supports x9
//        vSeeds.push_back(CDNSSeedData("dashjr.org", "dnsseed.bitcoin.dashjr.org")); // Luke Dashjr
//        vSeeds.push_back(CDNSSeedData("bitcoinstats.com", "seed.bitcoinstats.com", true)); // Christian Decker, supports x1 - xf
//        vSeeds.push_back(CDNSSeedData("xf2.org", "bitseed.xf2.org")); // Jeff Garzik
//        vSeeds.push_back(CDNSSeedData("bitcoin.jonasschnelli.ch", "seed.bitcoin.jonasschnelli.ch", true)); // Jonas Schnelli, only supports x1, x5, x9, and xd

        base58Prefixes[PUBKEY_ADDRESS] = std::vector<unsigned char>(1,52); //M or N
        base58Prefixes[SCRIPT_ADDRESS] = std::vector<unsigned char>(1,3); //2
//        base58Prefixes[SCRIPT_ADDRESS2] = std::vector<unsigned char>(1,5); //3
        base58Prefixes[SECRET_KEY] =     std::vector<unsigned char>(1,144); //z or 2
        base58Prefixes[EXT_PUBLIC_KEY] = boost::assign::list_of(0x03)(0x03)(0x05)(0x06).convert_to_container<std::vector<unsigned char> >(); //2233
        base58Prefixes[EXT_SECRET_KEY] = boost::assign::list_of(0x03)(0x05)(0x06)(0x06).convert_to_container<std::vector<unsigned char> >(); //2333

        vFixedSeeds = std::vector<SeedSpec6>(pnSeed6_main, pnSeed6_main + ARRAYLEN(pnSeed6_main));

        fMiningRequiresPeers = true;
        fDefaultConsistencyChecks = false;
        fRequireStandard = true;
        fMineBlocksOnDemand = false;

        checkpointData = (CCheckpointData) {
            boost::assign::map_list_of
            ( 0, uint256S(MAINNET_GENESIS_HASH))
        };

        chainTxData = ChainTxData{
            // Data as of block 00000000000000000166d612d5595e2b1cd88d71d695fc580af64d8da8658c23 (height 446482).
            0, // * UNIX timestamp of last known number of transactions
            0,  // * total number of transactions between genesis and that timestamp
                        //   (the tx=... number in the SetBestChain debug.log lines)
            0.0         // * estimated number of transactions per second after that timestamp
        };
    }
};
static CMainParams mainParams;

/**
 * Testnet (v3)
 */
class CTestNetParams : public CChainParams {
public:
    CTestNetParams() {
        strNetworkID = "test";
        consensus.nSubsidyHalvingInterval = 840000;
//        consensus.BIP34Height = 21111;
//        consensus.BIP34Hash = uint256S("0x0000000023b3a96d3484e5abb3755c413e7d41500f8e2a5c3f0dd01299cd8ef8");
//        consensus.BIP65Height = 581885; // 00000000007f6655f22f98e72ed80d8b06dc761d5da09df0fa1dc4be4f861eb6
//        consensus.BIP66Height = 330776; // 000000002104c8c45e99a8853285a3b592602a3ccde2b832481da85e9e4ba182
        consensus.powLimit = uint256S("00000000ffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
        consensus.nPowTargetTimespan = 3.5 * 24 * 60 * 60; // 3.5 days
        consensus.nPowTargetSpacing = 2.5 * 60;
        consensus.fPowAllowMinDifficultyBlocks = true;
        consensus.fPowNoRetargeting = false;
        consensus.nRuleChangeActivationThreshold = 1512; // 75% for testchains
        consensus.nMinerConfirmationWindow = 2016; // nPowTargetTimespan / nPowTargetSpacing
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].bit = 28;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nStartTime = 1199145601; // January 1, 2008
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nTimeout = 1230767999; // December 31, 2008

        // Deployment of BIP68, BIP112, and BIP113.
        consensus.vDeployments[Consensus::DEPLOYMENT_CSV].bit = 0;
        consensus.vDeployments[Consensus::DEPLOYMENT_CSV].nStartTime = 1456790400; // March 1st, 2016
        consensus.vDeployments[Consensus::DEPLOYMENT_CSV].nTimeout = 1493596800; // May 1st, 2017

        // Deployment of SegWit (BIP141, BIP143, and BIP147)
        consensus.vDeployments[Consensus::DEPLOYMENT_SEGWIT].bit = 1;
        consensus.vDeployments[Consensus::DEPLOYMENT_SEGWIT].nStartTime = 1462060800; // May 1st 2016
        consensus.vDeployments[Consensus::DEPLOYMENT_SEGWIT].nTimeout = 1493596800; // May 1st 2017

        // The best chain should have at least this much work.
//        consensus.nMinimumChainWork = uint256S("0x0000000000000000000000000000000000000000000000198b4def2baa9338d6");

        // By default assume that the signatures in ancestors of this block are valid.
//        consensus.defaultAssumeValid = uint256S("0x000000000871ee6842d3648317ccc8a435eb8cc3c2429aee94faff9ba26b05a0"); //1043841

        pchMessageStart[0] = 0x4d; //M 4d4f4554
        pchMessageStart[1] = 0x4f; //O
        pchMessageStart[2] = 0x45; //E
        pchMessageStart[3] = 0x54; //T
        nDefaultPort = 12233;
        nPruneAfterHeight = 1000;

        genesis = CreateGenesisBlock(1486016235, TESTNET_GENESIS_NONCE, 0x1d00ffff, 1, 50 * COIN, consensus);
        consensus.hashGenesisBlock = genesis.GetHash();
#ifdef FIND_GENESIS
        std::cout << "testnet genesis hash: " << genesis.GetHash().GetHex() << std::endl;
        std::cout << "testnet merkle hash: " << genesis.hashMerkleRoot.GetHex() << std::endl;
#else
        assert(consensus.hashGenesisBlock == uint256S(TESTNET_GENESIS_HASH));
        assert(genesis.hashMerkleRoot == uint256S(GENESIS_MERKLE_ROOT));
#endif
        vFixedSeeds.clear();
        vSeeds.clear();
        // nodes with support for servicebits filtering should be at the top
//        vSeeds.push_back(CDNSSeedData("testnetbitcoin.jonasschnelli.ch", "testnet-seed.bitcoin.jonasschnelli.ch", true));
//        vSeeds.push_back(CDNSSeedData("petertodd.org", "seed.tbtc.petertodd.org", true));
//        vSeeds.push_back(CDNSSeedData("bluematt.me", "testnet-seed.bluematt.me"));
//        vSeeds.push_back(CDNSSeedData("bitcoin.schildbach.de", "testnet-seed.bitcoin.schildbach.de"));

        base58Prefixes[PUBKEY_ADDRESS] = std::vector<unsigned char>(1,99); //g or h
        base58Prefixes[SCRIPT_ADDRESS] = std::vector<unsigned char>(1,138); //x
//        base58Prefixes[SCRIPT_ADDRESS2] = std::vector<unsigned char>(1,140); //y
        base58Prefixes[SECRET_KEY] =     std::vector<unsigned char>(1,135); //w
        base58Prefixes[EXT_PUBLIC_KEY] = boost::assign::list_of(0x04)(0x34)(0x86)(0xCF).convert_to_container<std::vector<unsigned char> >();
        base58Prefixes[EXT_SECRET_KEY] = boost::assign::list_of(0x04)(0x34)(0x85)(0x54).convert_to_container<std::vector<unsigned char> >();

        vFixedSeeds = std::vector<SeedSpec6>(pnSeed6_test, pnSeed6_test + ARRAYLEN(pnSeed6_test));

        fMiningRequiresPeers = true;
        fDefaultConsistencyChecks = false;
        fRequireStandard = false;
        fMineBlocksOnDemand = false;


        checkpointData = (CCheckpointData) {
            boost::assign::map_list_of
            ( 0, uint256S(TESTNET_GENESIS_HASH)),
        };

        chainTxData = ChainTxData{
            // Data as of block 00000000c2872f8f8a8935c8e3c5862be9038c97d4de2cf37ed496991166928a (height 1063660)
            0,
            0,
            0.0
        };

    }
};
static CTestNetParams testNetParams;

/**
 * Regression test
 */
class CRegTestParams : public CChainParams {
public:
    CRegTestParams() {
        strNetworkID = "regtest";
        consensus.nSubsidyHalvingInterval = 150;
        consensus.BIP34Height = 100000000; // BIP34 has not activated on regtest (far in the future so block v1 are not rejected in tests)
        consensus.BIP34Hash = uint256();
        consensus.BIP65Height = 1351; // BIP65 activated on regtest (Used in rpc activation tests)
        consensus.BIP66Height = 1251; // BIP66 activated on regtest (Used in rpc activation tests)
        consensus.powLimit = uint256S("7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
        consensus.nPowTargetTimespan = 3.5 * 24 * 60 * 60; // 3.5 days
        consensus.nPowTargetSpacing = 2.5 * 60;
        consensus.fPowAllowMinDifficultyBlocks = true;
        consensus.fPowNoRetargeting = true;
        consensus.nRuleChangeActivationThreshold = 108; // 75% for testchains
        consensus.nMinerConfirmationWindow = 144; // Faster than normal for regtest (144 instead of 2016)
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].bit = 28;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nStartTime = 0;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nTimeout = 999999999999ULL;
        consensus.vDeployments[Consensus::DEPLOYMENT_CSV].bit = 0;
        consensus.vDeployments[Consensus::DEPLOYMENT_CSV].nStartTime = 0;
        consensus.vDeployments[Consensus::DEPLOYMENT_CSV].nTimeout = 999999999999ULL;
        consensus.vDeployments[Consensus::DEPLOYMENT_SEGWIT].bit = 1;
        consensus.vDeployments[Consensus::DEPLOYMENT_SEGWIT].nStartTime = 0;
        consensus.vDeployments[Consensus::DEPLOYMENT_SEGWIT].nTimeout = 999999999999ULL;

        // The best chain should have at least this much work.
        consensus.nMinimumChainWork = uint256S("0x00");

        // By default assume that the signatures in ancestors of this block are valid.
        consensus.defaultAssumeValid = uint256S("0x00");

        pchMessageStart[0] = 0x4d; //M 4d4f4552
        pchMessageStart[1] = 0x4f; //O
        pchMessageStart[2] = 0x45; //E
        pchMessageStart[3] = 0x52; //R
        nDefaultPort = 12333;
        nPruneAfterHeight = 1000;

        genesis = CreateGenesisBlock(1486016282, REGTEST_GENESIS_NONCE, 0x207fffff, 1, 50 * COIN, consensus);
        consensus.hashGenesisBlock = genesis.GetHash();
#ifdef FIND_GENESIS
        std::cout << "regtest genensis hash: " << genesis.GetHash().GetHex() << std::endl;
        std::cout << "regtest hashmerkleroot: " << genesis.hashMerkleRoot.GetHex() << std::endl;
#else
        assert(consensus.hashGenesisBlock == uint256S(REGTEST_GENESIS_HASH));
        assert(genesis.hashMerkleRoot == uint256S(GENESIS_MERKLE_ROOT));
#endif
        vFixedSeeds.clear(); //!< Regtest mode doesn't have any fixed seeds.
        vSeeds.clear();      //!< Regtest mode doesn't have any DNS seeds.

        fMiningRequiresPeers = false;
        fDefaultConsistencyChecks = true;
        fRequireStandard = false;
        fMineBlocksOnDemand = true;

        checkpointData = (CCheckpointData){
            boost::assign::map_list_of
            ( 0, uint256S(REGTEST_GENESIS_HASH))
        };

        chainTxData = ChainTxData{
            0,
            0,
            0.0
        };

        base58Prefixes[PUBKEY_ADDRESS] = std::vector<unsigned char>(1,99); //g or h
        base58Prefixes[SCRIPT_ADDRESS] = std::vector<unsigned char>(1,138); //x
//        base58Prefixes[SCRIPT_ADDRESS2] = std::vector<unsigned char>(1,140); //y
        base58Prefixes[SECRET_KEY] =     std::vector<unsigned char>(1,135); //w
        base58Prefixes[EXT_PUBLIC_KEY] = boost::assign::list_of(0x04)(0x34)(0x86)(0xCF).convert_to_container<std::vector<unsigned char> >();
        base58Prefixes[EXT_SECRET_KEY] = boost::assign::list_of(0x04)(0x34)(0x85)(0x54).convert_to_container<std::vector<unsigned char> >();
    }

    void UpdateBIP9Parameters(Consensus::DeploymentPos d, int64_t nStartTime, int64_t nTimeout)
    {
        consensus.vDeployments[d].nStartTime = nStartTime;
        consensus.vDeployments[d].nTimeout = nTimeout;
    }
};
static CRegTestParams regTestParams;

static CChainParams *pCurrentParams = 0;

const CChainParams &Params() {
    assert(pCurrentParams);
    return *pCurrentParams;
}

CChainParams& Params(const std::string& chain)
{
    if (chain == CBaseChainParams::MAIN)
            return mainParams;
    else if (chain == CBaseChainParams::TESTNET)
            return testNetParams;
    else if (chain == CBaseChainParams::REGTEST)
            return regTestParams;
    else
        throw std::runtime_error(strprintf("%s: Unknown chain %s.", __func__, chain));
}

void SelectParams(const std::string& network)
{
    SelectBaseParams(network);
    pCurrentParams = &Params(network);
}

void UpdateRegtestBIP9Parameters(Consensus::DeploymentPos d, int64_t nStartTime, int64_t nTimeout)
{
    regTestParams.UpdateBIP9Parameters(d, nStartTime, nTimeout);
}
 
