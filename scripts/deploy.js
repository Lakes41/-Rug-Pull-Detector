const hre = require("hardhat");

async function main() {
  console.log("Deploying RiskRegistry contract...");

  // Get the bonding token address (for testing, we'll deploy a mock ERC20)
  const MockToken = await hre.ethers.getContractFactory("MockERC20");
  const mockToken = await MockToken.deploy("Mock Bonding Token", "MBT", hre.ethers.parseEther("1000000"));
  await mockToken.waitForDeployment();
  const tokenAddress = await mockToken.getAddress();
  console.log("MockERC20 deployed to:", tokenAddress);

  // Deploy RiskRegistry
  const RiskRegistry = await hre.ethers.getContractFactory("RiskRegistry");
  const riskRegistry = await RiskRegistry.deploy(tokenAddress);
  await riskRegistry.waitForDeployment();
  const registryAddress = await riskRegistry.getAddress();
  console.log("RiskRegistry deployed to:", registryAddress);

  // Verify deployment
  console.log("\nDeployment Summary:");
  console.log("==================");
  console.log("Bonding Token:", tokenAddress);
  console.log("RiskRegistry:", registryAddress);
  console.log("\nNetwork:", hre.network.name);
  console.log("Deployer:", (await hre.ethers.getSigners())[0].address);

  // Save deployment info
  const deploymentInfo = {
    network: hre.network.name,
    chainId: (await hre.ethers.provider.getNetwork()).chainId.toString(),
    deployer: (await hre.ethers.getSigners())[0].address,
    contracts: {
      MockERC20: tokenAddress,
      RiskRegistry: registryAddress
    },
    timestamp: new Date().toISOString()
  };

  const fs = require("fs");
  fs.writeFileSync(
    `./deployments/${hre.network.name}.json`,
    JSON.stringify(deploymentInfo, null, 2)
  );
  console.log("\nDeployment info saved to deployments/" + hre.network.name + ".json");
}

main()
  .then(() => process.exit(0))
  .catch((error) => {
    console.error(error);
    process.exit(1);
  });
