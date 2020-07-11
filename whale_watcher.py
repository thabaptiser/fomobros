from collections import defaultdict
import json
import requests
import time

TRANSFER_SIGNATURE = (
    "0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef"
)
provider_url = "https://mainnet.infura.io/v3/0e1aad019aa84a69b6204406e7ff2f04"
signatures = [TRANSFER_SIGNATURE]
shitcoin_addresses = ["0xba100000625a3754423978a60c9317c58a424e3d"]
wallets = ["0x57757e3d981446d585af0d9ae4d7df6d64647806"]


def data_to_array_of_32bytes(data):
    if data.startswith("0x"):
        data = data[2:]
    assert len(data) % 64 == 0
    return [data[x * 64 : x * 64 + 64] for x in range(0, len(data) // 64)]


def bytes32_to_address(bytes32):
    # 26 because it starts with 0x, and we need to remove 24 zeroes after that
    if bytes32.startswith("0x"):
        bytes32 = bytes32[2:]
    return "0x" + bytes32[24:]


def bytes32_to_int(bytes32):
    return int(bytes32, 16)


def get_latest_block():
    call = {
            "jsonrpc": "2.0",
            "method": "eth_getBlockByNumber",
            "params": ["latest", False],
            "id": 1,
        }
    ret = node_call(call)
    data = json.loads(ret.text)
    return data['result']['number']


def get_logs(latest_block):
    call = {
        "jsonrpc": "2.0",
        "id": 1,
        "method": "eth_getLogs",
        "params": [
            {
                "address": shitcoin_addresses,
                "topics": signatures,
                "fromBlock": latest_block,
            }
        ],
    }
    ret = node_call(call)
    data = json.loads(ret.text)
    block_number = latest_block
    for log in data["result"]:
        topics = log["topics"]
        data = data_to_array_of_32bytes(log["data"])
        log_index = int(log["logIndex"], 16)
        tx_hash = log["transactionHash"]
        block_number = log["blockNumber"]
        address = log["address"]
        if topics[0] == TRANSFER_SIGNATURE:
            parse_erc20_transfer(address, topics, data)
    return block_number


def parse_erc20_transfer(token_address, topics, data):
    source_address = bytes32_to_address(topics[1])
    destination_address = bytes32_to_address(topics[2])
    transfer_amount = bytes32_to_int(data[0])
    if source_address in wallets or destination_address in wallets:
        send_discord_message(
            token_address, source_address, destination_address, transfer_amount
        )


def send_discord_message(
    token_address, source_address, destination_address, transfer_amount
):
    # TODO: format and send to discord
    pass


def node_call(data):
    result = requests.post(provider_url, data=json.dumps(data))
    return result


latest_block = get_latest_block()
while True:
    latest_block = get_logs(latest_block)
    print("Last block num with logs: ", latest_block)
    time.sleep(5)
