// SPDX-License-Identifier: MIT
pragma solidity ^0.8.17;

import "./DN404.sol";
import "./DN404Mirror.sol";
import "contract-allow-list/contracts/ERC721AntiScam/restrictApprove/ERC721RestrictApprove.sol";
import "@openzeppelin/contracts/access/AccessControl.sol";
import {Ownable} from "solady/src/auth/Ownable.sol";
import {LibString} from "solady/src/utils/LibString.sol";
import {SafeTransferLib} from "solady/src/utils/SafeTransferLib.sol";
import {MerkleProofLib} from "solady/src/utils/MerkleProofLib.sol";
import {RevokableDefaultOperatorFilterer} from "operator-filter-registry/src/RevokableDefaultOperatorFilterer.sol";

contract TESTDN404 is DN404, Ownable, RevokableDefaultOperatorFilterer, ERC721RestrictApprove, AccessControl {
    // カスタムエラーを定義
    error FractionalTransferNotAllowed();

    string private _name;
    string private _symbol;
    string private _baseURI;
    bytes32 private _allowlistRoot;

    uint96 public publicPrice;
    uint96 public allowlistPrice;
    uint32 public totalMinted;
    bool public live;

    uint32 public maxPerWallet = 100;
    uint32 public maxSupply = 100;
    uint256 private _mintRatio = 10;
    uint8 private _decimals = 18;

    error InvalidProof();
    error InvalidMint();
    error InvalidPrice();
    error TotalSupplyReached();
    error NotLive();

    bytes32 public constant ADMIN = keccak256("ADMIN");

    constructor(
        string memory name_,
        string memory symbol_,
        bytes32 allowlistRoot_,
        uint96 publicPrice_,
        uint96 allowlistPrice_,
        uint96 initialTokenSupply,
        address initialSupplyOwner
    ) DN404(name_, symbol_, initialTokenSupply, initialSupplyOwner) {
        // 1. オーナーの初期化
        _initializeOwner(msg.sender);

        // 2. ロールの設定
        _setupRole(DEFAULT_ADMIN_ROLE, msg.sender);
        grantRole(ADMIN, msg.sender);

        // 3. 他の初期化
        _name = name_;
        _symbol = symbol_;
        _allowlistRoot = allowlistRoot_;
        publicPrice = publicPrice_;
        allowlistPrice = allowlistPrice_;

        address mirror = address(new DN404Mirror(msg.sender));
        _initializeDN404(initialTokenSupply, initialSupplyOwner, mirror);

        // 4. CALの初期化
        setCALLevel(1);
        _setCAL(0xdbaa28cBe70aF04EbFB166b1A3E8F8034e5B9FC7);
    }

    function _unit() internal view override returns (uint256) {
        return _mintRatio * 10**18;
    }

    function setMintRatio(uint256 newRatio) public onlyOwner {
        _mintRatio = newRatio;
    }

    modifier onlyLive() {
        if (!live) {
            revert NotLive();
        }
        _;
    }

    modifier checkPrice(uint256 price, uint256 nftAmount) {
        if (price * nftAmount != msg.value) {
            revert InvalidPrice();
        }
        _;
    }

    function setDecimals(uint8 newDecimals) public onlyOwner {
        _decimals = newDecimals;
    }

    function setMaxPerWallet(uint32 _maxPerWallet) public onlyOwner {
        maxPerWallet = _maxPerWallet;
    }

    function setMaxSupply(uint32 _maxSupply) public onlyOwner {
        maxSupply = _maxSupply;
    }

    modifier checkAndUpdateTotalMinted(uint256 nftAmount) {
        uint256 newTotalMinted = uint256(totalMinted) + nftAmount;
        if (newTotalMinted > maxSupply) {
            revert TotalSupplyReached();
        }
        totalMinted = uint32(newTotalMinted);
        _;
    }

    modifier checkAndUpdateBuyerMintCount(uint256 nftAmount) {
        uint256 currentMintCount = _getAux(msg.sender);
        uint256 newMintCount = currentMintCount + nftAmount;
        if (newMintCount > maxPerWallet) {
            revert InvalidMint();
        }
        _setAux(msg.sender, uint88(newMintCount));
        _;
    }

    function mint(uint256 tokenAmount)
        public
        payable
        onlyLive
        checkPrice(publicPrice, tokenAmount)
        checkAndUpdateBuyerMintCount(tokenAmount)
        checkAndUpdateTotalMinted(tokenAmount)
    {
        _mint(msg.sender, tokenAmount * 10 ** _decimals);
    }

    function allowlistMint(uint256 tokenAmount, bytes32[] calldata proof)
        public
        payable
        onlyLive
        checkPrice(allowlistPrice, tokenAmount)
        checkAndUpdateBuyerMintCount(tokenAmount)
        checkAndUpdateTotalMinted(tokenAmount)
    {
        bytes32 leaf = keccak256(abi.encodePacked(msg.sender));
        if (!MerkleProofLib.verify(proof, _allowlistRoot, leaf)) {
            revert InvalidProof();
        }

        _mint(msg.sender, tokenAmount * 10 ** _decimals);
    }

    function mintNFT(uint256 nftAmount)
        public
        payable
        onlyLive
        checkPrice(publicPrice, nftAmount)
        checkAndUpdateBuyerMintCount(nftAmount)
        checkAndUpdateTotalMinted(nftAmount)
    {
        _mint(msg.sender, nftAmount * _unit());
    }

    function allowlistNFTMint(uint256 nftAmount, bytes32[] calldata proof)
        public
        payable
        onlyLive
        checkPrice(allowlistPrice, nftAmount)
        checkAndUpdateBuyerMintCount(nftAmount)
        checkAndUpdateTotalMinted(nftAmount)
    {
        bytes32 leaf = keccak256(abi.encodePacked(msg.sender));
        if (!MerkleProofLib.verify(proof, _allowlistRoot, leaf)) {
            revert InvalidProof();
        }

        _mint(msg.sender, nftAmount * _unit());
    }

    function setBaseURI(string memory baseURI_) public onlyOwner {
        _baseURI = baseURI_;
    }

    function setPrices(uint96 publicPrice_, uint96 allowlistPrice_) public onlyOwner {
        publicPrice = publicPrice_;
        allowlistPrice = allowlistPrice_;
    }

    function toggleLive() public onlyOwner {
        live = !live;
    }

    function withdraw() public onlyOwner {
        SafeTransferLib.safeTransferAllETH(msg.sender);
    }

    function name() public view override returns (string memory) {
        return _name;
    }

    function symbol() public view override returns (string memory) {
        return _symbol;
    }

    function tokenURI(uint256 tokenId) public view override returns (string memory result) {
        if (bytes(_baseURI).length != 0) {
            result = string(abi.encodePacked(_baseURI, LibString.toString(tokenId), ".json"));
        }
    }

    function transfer(address to, uint256 amount) public override returns (bool) {
        require(amount % (_mintRatio * 10 ** _decimals) == 0, "Transfer amount must be a multiple of mint ratio.");
        return super.transfer(to, amount);
    }

    function transferFrom(address from, address to, uint256 amount) public override returns (bool) {
        require(amount % (_mintRatio * 10 ** _decimals) == 0, "Transfer amount must be a multiple of mint ratio.");
        return super.transferFrom(from, to, amount);
    }

    function _exists(uint256 tokenId) internal view override(DN404, ERC721RestrictApprove) returns (bool) {
        return DN404._exists(tokenId);
    }

    function _mint(address to, uint256 amount) internal override(DN404, ERC721RestrictApprove) {
        DN404._mint(to, amount);
    }

    function _transfer(address from, address to, uint256 tokenId) internal override(DN404, ERC721RestrictApprove) {
        DN404._transfer(from, to, tokenId);
    }

    function balanceOf(address owner) public view override(DN404, ERC721RestrictApprove) returns (uint256) {
        return DN404.balanceOf(owner);
    }

    function totalSupply() public view override(DN404, ERC721RestrictApprove) returns (uint256) {
        return DN404.totalSupply();
    }

    function setCALLevel(uint256 level) external override onlyRole(ADMIN) {
        CALLevel = level;
    }

    function setCAL(address calAddress) external override onlyRole(ADMIN) {
        _setCAL(calAddress);
    }

    function supportsInterface(bytes4 interfaceId)
        public
        view
        override(DN404, ERC721RestrictApprove, AccessControl)
        returns (bool)
    {
        return DN404.supportsInterface(interfaceId) ||
            ERC721RestrictApprove.supportsInterface(interfaceId) ||
            AccessControl.supportsInterface(interfaceId);
    }
}
