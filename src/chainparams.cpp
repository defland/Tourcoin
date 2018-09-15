// Copyright (c) 2010 Satoshi Nakamoto
// Copyright (c) 2009-2014 The Bitcoin Core developers
// Copyright (c) 2014-2017 The Dash Core developers
// Copyright (c) 2017-2018 The Tour Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.
#include <iostream>

#include "chainparams.h"
#include "consensus/merkle.h"

#include "tinyformat.h"
#include "util.h"
#include "utilstrencodings.h"
#include "arith_uint256.h"
#include <assert.h>

#include <boost/assign/list_of.hpp>

#include "chainparamsseeds.h"

#include <fstream>
#include <iostream>
#include <string>


using std::fstream;

static CBlock CreateGenesisBlock(const char* pszTimestamp, const CScript& genesisOutputScript, uint32_t nTime, uint32_t nNonce, uint32_t nBits, int32_t nVersion, const CAmount& genesisReward)
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
    genesis.vtx.push_back(txNew);
    genesis.hashPrevBlock.SetNull();
    genesis.hashMerkleRoot = BlockMerkleRoot(genesis);
    return genesis;
}


static CBlock CreateGenesisBlock(uint32_t nTime, uint32_t nNonce, uint32_t nBits, int32_t nVersion, const CAmount& genesisReward)
{
    const char* pszTimestamp = "7/3/2018 Bank of England raises UK interest rates";
    const CScript genesisOutputScript = CScript() << ParseHex("045fbebd02f0ddb33501914c7a7b717b1247c5300bd39ac02d5613deee3ab84f84da198179fe7167800e1f5cc962e847f0129c36a6c849113c165e087b9ca8bf23") << OP_CHECKSIG;
    return CreateGenesisBlock(pszTimestamp, genesisOutputScript, nTime, nNonce, nBits, nVersion, genesisReward);
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
        consensus.nSubsidyHalvingInterval = 418400; // every  2 years
        consensus.nMasternodePaymentsStartBlock = 100; // not true, but it's ok as long as it's less then nMasternodePaymentsIncreaseBlock
        consensus.nMasternodePaymentsIncreaseBlock = 2100000000; // not used
        consensus.nMasternodePaymentsIncreasePeriod = 576*30; // not used
        consensus.nInstantSendKeepLock = 24;
        consensus.nBudgetPaymentsStartBlock = 418400; // 
        consensus.nBudgetPaymentsCycleBlocks = 16616;
        consensus.nBudgetPaymentsWindowBlocks = 100;
        consensus.nBudgetProposalEstablishingTime = 60*60*24;
        consensus.nSuperblockStartBlock = 2100000000; // year 10000+
        consensus.nSuperblockCycle = 16616;
        consensus.nGovernanceMinQuorum = 10;
        consensus.nGovernanceFilterElements = 20000;
        consensus.nMasternodeMinimumConfirmations = 15;
        consensus.nMajorityEnforceBlockUpgrade = 750;
        consensus.nMajorityRejectBlockOutdated = 950;
        consensus.nMajorityWindow = 1000;
        consensus.BIP34Height = 0; // FIX
        consensus.BIP34Hash = uint256S("0x00000049fbb8a2ecae21a123c6cd7c33facac2ceab2def9a5307f12aaabb816b"); // FIX
        consensus.powLimit = uint256S("00000fffff000000000000000000000000000000000000000000000000000000");
        consensus.nPowTargetTimespan = 6 * 60; // Tour: 360 seconds
        consensus.nPowTargetSpacing = 2 * 60; // Tour: 120 seconds
        consensus.fPowAllowMinDifficultyBlocks = false;
        consensus.fPowNoRetargeting = false;
        consensus.nRuleChangeActivationThreshold = 1916; // 95% of 2016
        consensus.nMinerConfirmationWindow = 2016; // nPowTargetTimespan / nPowTargetSpacing
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].bit = 28;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nStartTime = 1199145601; // January 1, 2008
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nTimeout = 1230767999; // December 31, 2008

        // Deployment of BIP68, BIP112, and BIP113.
        consensus.vDeployments[Consensus::DEPLOYMENT_CSV].bit = 0;
        consensus.vDeployments[Consensus::DEPLOYMENT_CSV].nStartTime = 1502280000; // Aug 9th, 2017
        consensus.vDeployments[Consensus::DEPLOYMENT_CSV].nTimeout = 1533816000; // Aug 9th, 2018

        /**
         * The message start string is designed to be unlikely to occur in normal data.
         * The characters are rarely used upper ASCII, not valid as UTF-8, and produce
         * a large 32-bit integer with any alignment.
         */
        pchMessageStart[0] = 0x1b;
        pchMessageStart[1] = 0xb3;
        pchMessageStart[2] = 0xb4;
        pchMessageStart[3] = 0xd5;
        vAlertPubKey = ParseHex("045fbebd02f0ddb33501914c7a7b717b1247c5300bd39ac02d5613deee3ab84f84da198179fe7167800e1f5cc962e847f0129c36a6c849113c165e087b9ca8bf23");
        nDefaultPort = 11093;
        nMaxTipAge = 6 * 60 * 60; // ~144 blocks behind -> 2 x fork detection time, was 24 * 60 * 60 in bitcoin
        nPruneAfterHeight = 100000;

        genesis = CreateGenesisBlock(1533337899, 3325733, 0x1e0fffff, 1, 50 * COIN);

        consensus.hashGenesisBlock = genesis.GetHash();

        assert(consensus.hashGenesisBlock == uint256S("0x000008582c03d888e711f9d981a5f5eeaebc55c460e2f8ed945b953776e6c163"));
        assert(genesis.hashMerkleRoot == uint256S("0x2182e65f9f64a1ec1b454b2c7fe6a5bef7b2a6a2e80dad953715cda6cc6c4f06"));


        // Tour addresses start with 'S'
        base58Prefixes[PUBKEY_ADDRESS] = std::vector<unsigned char>(1,63);
        // Tour script addresses start with '7'
        base58Prefixes[SCRIPT_ADDRESS] = std::vector<unsigned char>(1,16);
        // Tour private keys start with '2' or 'z' (?)
        base58Prefixes[SECRET_KEY] =     std::vector<unsigned char>(1,144);
        // Tour BIP32 pubkeys start with 'xpub' (Bitcoin defaults)
        base58Prefixes[EXT_PUBLIC_KEY] = boost::assign::list_of(0x04)(0x88)(0xB2)(0x1E).convert_to_container<std::vector<unsigned char> >();
        // Tour BIP32 prvkeys start with 'xprv' (Bitcoin defaults)
        base58Prefixes[EXT_SECRET_KEY] = boost::assign::list_of(0x04)(0x88)(0xAD)(0xE4).convert_to_container<std::vector<unsigned char> >();
        // Tour BIP44 coin type is '5'
        base58Prefixes[EXT_COIN_TYPE]  = boost::assign::list_of(0x80)(0x00)(0x00)(0x05).convert_to_container<std::vector<unsigned char> >();

        vFixedSeeds = std::vector<SeedSpec6>(pnSeed6_main, pnSeed6_main + ARRAYLEN(pnSeed6_main));

        fMiningRequiresPeers = false;
        fDefaultConsistencyChecks = false;
        fRequireStandard = true;
        fMineBlocksOnDemand = false;
        fTestnetToBeDeprecatedFieldRPC = false;

        nPoolMaxTransactions = 3;
        nFulfilledRequestExpireTime = 60*60; // fulfilled requests expire in 1 hour
        strSporkPubKey = "048458ecad5cfde2a01ad656ff8abdcc3dc28c70deb192daee25fb7202e4594a6ee1e97516c7a080bfc2b2ee82dc179e168ed87bde8ccd98d3ab1f7df053fa0c91";
        strMasternodePaymentsPubKey = "048458ecad5cfde2a01ad656ff8abdcc3dc28c70deb192daee25fb7202e4594a6ee1e97516c7a080bfc2b2ee82dc179e168ed87bde8ccd98d3ab1f7df053fa0c91";



        checkpointData = (CCheckpointData) {
            boost::assign::map_list_of
            (    0, uint256S("0x000008582c03d888e711f9d981a5f5eeaebc55c460e2f8ed945b953776e6c163"))
            (26708, uint256S("0x00000000ce7249d6ab1e64f3ab88799118193cc7fdd711a5221c425b6f1216ff"))
            (28800, uint256S("0x000000005c6a6e5a09e691335aaf33334bda2a5e535f0c326132a8b57800e3d5")),
            1537034549, // * UNIX timestamp of last checkpoint block
            31797,   // * total number of transactions between genesis and last checkpoint
                        //   (the tx=... number in the SetBestChain debug.log lines)
            3500        // * estimated number of transactions per day after checkpoint

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
        consensus.nSubsidyHalvingInterval = 262800;
        consensus.nMasternodePaymentsStartBlock = 5; // not true, but it's ok as long as it's less then nMasternodePaymentsIncreaseBlock
        consensus.nMasternodePaymentsIncreaseBlock = 158000;
        consensus.nMasternodePaymentsIncreasePeriod = 576*30;
        consensus.nInstantSendKeepLock = 6;
        consensus.nBudgetPaymentsStartBlock = 2100000000;
        consensus.nBudgetPaymentsCycleBlocks = 50;
        consensus.nBudgetPaymentsWindowBlocks = 10;
        consensus.nBudgetProposalEstablishingTime = 60*20;
        consensus.nSuperblockStartBlock = 2100000000; // NOTE: Should satisfy nSuperblockStartBlock > nBudgetPeymentsStartBlock
        consensus.nSuperblockCycle = 24; // Superblocks can be issued hourly on testnet
        consensus.nGovernanceMinQuorum = 1;
        consensus.nGovernanceFilterElements = 500;
        consensus.nMasternodeMinimumConfirmations = 1;
        consensus.nMajorityEnforceBlockUpgrade = 51;
        consensus.nMajorityRejectBlockOutdated = 75;
        consensus.nMajorityWindow = 100;
        consensus.BIP34Height = 21111; // FIX
        consensus.BIP34Hash = uint256S("0x0000000023b3a96d3484e5abb3755c413e7d41500f8e2a5c3f0dd01299cd8ef8"); // FIX
        consensus.powLimit = uint256S("00000fffff000000000000000000000000000000000000000000000000000000");
        consensus.nPowTargetTimespan = 2 * 60 * 60; // Tour: 1 hour, 24 blocks
        consensus.nPowTargetSpacing = 0.5 * 60; // Tour: 150 seconds
        consensus.fPowAllowMinDifficultyBlocks = true;
        consensus.fPowNoRetargeting = false;
        consensus.nRuleChangeActivationThreshold = 1512; // 75% for testchains
        consensus.nMinerConfirmationWindow = 2016; // nPowTargetTimespan / nPowTargetSpacing
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].bit = 28;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nStartTime = 1199145601; // January 1, 2008
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nTimeout = 1230767999; // December 31, 2008

        // Deployment of BIP68, BIP112, and BIP113.
        consensus.vDeployments[Consensus::DEPLOYMENT_CSV].bit = 0;
        consensus.vDeployments[Consensus::DEPLOYMENT_CSV].nStartTime = 1502280000; // Aug 9th, 2017
        consensus.vDeployments[Consensus::DEPLOYMENT_CSV].nTimeout = 1533816000; // Aug 9th, 2018

        pchMessageStart[0] = 0xd3;
        pchMessageStart[1] = 0x2d;
        pchMessageStart[2] = 0xa5;
        pchMessageStart[3] = 0x7c;
        vAlertPubKey = ParseHex("0450fbc8f012683ad3a3319c8744bbaefea36d92d291a845e813b51343f31b66e3250edd00d739a2d3426455a6ec6c7b1c3432f1a5d69a778dfe357b5e80e2952a");
        nDefaultPort = 18092;
        nMaxTipAge = 0x7fffffff; // allow mining on top of old blocks for testnet
        nPruneAfterHeight = 1000;


        genesis = CreateGenesisBlock(1528168841, 197578, 0x1e0fffff, 1, 50 * COIN);

        consensus.hashGenesisBlock = genesis.GetHash();


    //    assert(consensus.hashGenesisBlock == uint256S("0x00000989f858be5b0fb306726691acb1f419af8fba3970efdb55e46b03f9c62e"));
    //    assert(genesis.hashMerkleRoot == uint256S("0x2182e65f9f64a1ec1b454b2c7fe6a5bef7b2a6a2e80dad953715cda6cc6c4f06"));

        vFixedSeeds.clear();
        vSeeds.clear();

        // Testnet Tour addresses start with 'n'
        base58Prefixes[PUBKEY_ADDRESS] = std::vector<unsigned char>(1,65);
        // Testnet Tour script addresses start with '9'
        base58Prefixes[SCRIPT_ADDRESS] = std::vector<unsigned char>(1,20);
        // Testnet private keys start with '9' or 'c' (Bitcoin defaults) (?)
        base58Prefixes[SECRET_KEY] =     std::vector<unsigned char>(1,240);
        // Testnet Tour BIP32 pubkeys start with 'tpub' (Bitcoin defaults)
        base58Prefixes[EXT_PUBLIC_KEY] = boost::assign::list_of(0x04)(0x35)(0x87)(0xCF).convert_to_container<std::vector<unsigned char> >();
        // Testnet Tour BIP32 prvkeys start with 'tprv' (Bitcoin defaults)
        base58Prefixes[EXT_SECRET_KEY] = boost::assign::list_of(0x04)(0x35)(0x83)(0x94).convert_to_container<std::vector<unsigned char> >();
        // Testnet Tour BIP44 coin type is '1' (All coin's testnet default)
        base58Prefixes[EXT_COIN_TYPE]  = boost::assign::list_of(0x80)(0x00)(0x00)(0x01).convert_to_container<std::vector<unsigned char> >();

        vFixedSeeds = std::vector<SeedSpec6>(pnSeed6_test, pnSeed6_test + ARRAYLEN(pnSeed6_test));

        fMiningRequiresPeers = false;
        fDefaultConsistencyChecks = false;
        fRequireStandard = false;
        fMineBlocksOnDemand = false;
        fTestnetToBeDeprecatedFieldRPC = true;

        nPoolMaxTransactions = 3;
        nFulfilledRequestExpireTime = 5*60; // fulfilled requests expire in 5 minutes
        strSporkPubKey = "04b78fb44d7523692e23b37c71c8cb8647b3ab5c122e2f7feb4bb38d37de8eefc09fbae03ca5b9b96751cc77d30b20b336a3f78612452a196ccd099adba433ed55";
        strMasternodePaymentsPubKey = "04b78fb44d7523692e23b37c71c8cb8647b3ab5c122e2f7feb4bb38d37de8eefc09fbae03ca5b9b96751cc77d30b20b336a3f78612452a196ccd099adba433ed55";
/*
        checkpointData = (CCheckpointData) {
            boost::assign::map_list_of
		(0, uint256S("0xaa57a0f8722554ecdb6f53080530feedf537d61a3452693cec25a6d195ea7226")),
		1533323291,
		0,
		100

            ( 0, uint256S("0x000004fdaaaa56214e74df55a214a2a2a26b50ba02f7d7efe7b255f7661e33ac")),
            
            1528168841, // * UNIX timestamp of last checkpoint block
            0,     // * total number of transactions between genesis and last checkpoint
                        //   (the tx=... number in the SetBestChain debug.log lines)
            500         // * etourated number of transactions per day after checkpoint
        };
*/
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
        consensus.nSubsidyHalvingInterval = 418400;
        consensus.nMasternodePaymentsStartBlock = 100;
        consensus.nMasternodePaymentsIncreaseBlock = 2100000000;
        consensus.nMasternodePaymentsIncreasePeriod = 576*30;
        consensus.nInstantSendKeepLock = 24;
        consensus.nBudgetPaymentsStartBlock = 418400;
        consensus.nBudgetPaymentsCycleBlocks = 16616;
        consensus.nBudgetPaymentsWindowBlocks = 100;
        consensus.nBudgetProposalEstablishingTime = 60*20;
        consensus.nSuperblockStartBlock = 2100000000;
        consensus.nSuperblockCycle = 10;
        consensus.nGovernanceMinQuorum = 1;
        consensus.nGovernanceFilterElements = 100;
        consensus.nMasternodeMinimumConfirmations = 1;
        consensus.nMajorityEnforceBlockUpgrade = 750;
        consensus.nMajorityRejectBlockOutdated = 950;
        consensus.nMajorityWindow = 1000;
        consensus.BIP34Height = -1; // BIP34 has not necessarily activated on regtest
        consensus.BIP34Hash = uint256();
        consensus.powLimit = uint256S("7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
        consensus.nPowTargetTimespan = 6 * 60; // Tour: 1 hour, 24 blocks
        consensus.nPowTargetSpacing = 2.0 * 60; // Tour: 150 seconds
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

        pchMessageStart[0] = 0xa2;
        pchMessageStart[1] = 0xb4;
        pchMessageStart[2] = 0xd6;
        pchMessageStart[3] = 0x7a;
        nMaxTipAge = 6 * 60 * 60; // ~144 blocks behind -> 2 x fork detection time, was 24 * 60 * 60 in bitcoin
        nDefaultPort = 28092;
        nPruneAfterHeight = 1000;

        genesis = CreateGenesisBlock(1528168841, 0, 0x207fffff, 1, 50 * COIN);
	
        consensus.hashGenesisBlock = genesis.GetHash();

     //   assert(consensus.hashGenesisBlock == uint256S("0x00000989f858be5b0fb306726691acb1f419af8fba3970efdb55e46b03f9c62e"));
     //   assert(genesis.hashMerkleRoot == uint256S("0x2182e65f9f64a1ec1b454b2c7fe6a5bef7b2a6a2e80dad953715cda6cc6c4f06"));


        vFixedSeeds.clear(); //! Regtest mode doesn't have any fixed seeds.
        vSeeds.clear();  //! Regtest mode doesn't have any DNS seeds.

        fMiningRequiresPeers = false;
        fDefaultConsistencyChecks = true;
        fRequireStandard = false;
        fMineBlocksOnDemand = true;
        fTestnetToBeDeprecatedFieldRPC = false;

        nFulfilledRequestExpireTime = 5*60; // fulfilled requests expire in 5 minutes
/*
        checkpointData = (CCheckpointData){
            boost::assign::map_list_of
		(0, uint256S("0xaa57a0f8722554ecdb6f53080530feedf537d61a3452693cec25a6d195ea7226")),
		1533323291,
		0,
		0
*/

/*
            ( 0, uint256S("0x3fcdf00e807a1ce0dab942a716fb2c683e997894da24b37e70b23adffcd28d07")),
            0,
            0,
            0

        };
*/

        // Regtest Tour addresses start with 't'
        base58Prefixes[PUBKEY_ADDRESS] = std::vector<unsigned char>(1,127);
        // Regtest Tour script addresses start with '9'
        base58Prefixes[SCRIPT_ADDRESS] = std::vector<unsigned char>(1,20);
        // Regtest private keys start with '9' or 'c' (Bitcoin defaults) (?)
        base58Prefixes[SECRET_KEY] =     std::vector<unsigned char>(1,240);
        // Regtest Tour BIP32 pubkeys start with 'tpub' (Bitcoin defaults)
        base58Prefixes[EXT_PUBLIC_KEY] = boost::assign::list_of(0x04)(0x35)(0x87)(0xCF).convert_to_container<std::vector<unsigned char> >();
        // Regtest Tour BIP32 prvkeys start with 'tprv' (Bitcoin defaults)
        base58Prefixes[EXT_SECRET_KEY] = boost::assign::list_of(0x04)(0x35)(0x83)(0x94).convert_to_container<std::vector<unsigned char> >();
        // Regtest Tour BIP44 coin type is '1' (All coin's testnet default)
        base58Prefixes[EXT_COIN_TYPE]  = boost::assign::list_of(0x80)(0x00)(0x00)(0x01).convert_to_container<std::vector<unsigned char> >();
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


