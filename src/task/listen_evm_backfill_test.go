package task

import (
	"context"
	"fmt"
	"math/big"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/GMWalletApp/epusdt/internal/testutil"
	"github.com/GMWalletApp/epusdt/model/dao"
	"github.com/GMWalletApp/epusdt/model/data"
	"github.com/GMWalletApp/epusdt/model/mdb"
	"github.com/ethereum/go-ethereum"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/ethclient"
	"github.com/ethereum/go-ethereum/rpc"
)

type backfillRangeRPCError struct {
	code    int
	message string
}

func (e backfillRangeRPCError) Error() string  { return e.message }
func (e backfillRangeRPCError) ErrorCode() int { return e.code }

type adaptiveBackfillRPC struct {
	mu              sync.Mutex
	ranges          []int64
	firstSuccessRun bool
}

func (s *adaptiveBackfillRPC) GetBlockByNumber(context.Context, rpc.BlockNumber, bool) (*types.Header, error) {
	return &types.Header{
		ParentHash:  common.Hash{},
		UncleHash:   types.EmptyUncleHash,
		Coinbase:    common.Address{},
		Root:        common.Hash{},
		TxHash:      types.EmptyTxsHash,
		ReceiptHash: types.EmptyReceiptsHash,
		Bloom:       types.Bloom{},
		Difficulty:  big.NewInt(0),
		Number:      big.NewInt(300),
		GasLimit:    30_000_000,
		GasUsed:     0,
		Time:        1_700_000_000,
		Extra:       []byte{},
		MixDigest:   common.Hash{},
		Nonce:       types.BlockNonce{},
	}, nil
}

func (s *adaptiveBackfillRPC) GetLogs(ctx context.Context, query map[string]interface{}) ([]types.Log, error) {
	fromBlock, err := rpcBlockNumberFromQuery(query, "fromBlock")
	if err != nil {
		return nil, err
	}
	toBlock, err := rpcBlockNumberFromQuery(query, "toBlock")
	if err != nil {
		return nil, err
	}
	blocks := toBlock - fromBlock + 1

	s.mu.Lock()
	s.ranges = append(s.ranges, blocks)
	if blocks > 50 {
		s.mu.Unlock()
		return nil, backfillRangeRPCError{code: -32602, message: "eth_getLogs is limited to 0 - 50 blocks range"}
	}
	if !s.firstSuccessRun {
		s.firstSuccessRun = true
		s.mu.Unlock()
		return []types.Log{}, nil
	}
	s.mu.Unlock()

	<-ctx.Done()
	return nil, ctx.Err()
}

func (s *adaptiveBackfillRPC) attemptedRanges() []int64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]int64(nil), s.ranges...)
}

func rpcBlockNumberFromQuery(query map[string]interface{}, key string) (int64, error) {
	raw, ok := query[key].(string)
	if !ok {
		return 0, fmt.Errorf("missing %s", key)
	}
	value, err := strconv.ParseInt(strings.TrimPrefix(raw, "0x"), 16, 64)
	if err != nil {
		return 0, fmt.Errorf("invalid %s: %q", key, raw)
	}
	return value, nil
}

func TestEvmBackfillShrinksRejectedRangeAndPersistsCursor(t *testing.T) {
	cleanup := testutil.SetupTestDatabases(t)
	defer cleanup()

	if err := dao.Mdb.Model(&mdb.Chain{}).
		Where("network = ?", mdb.NetworkBsc).
		Updates(map[string]interface{}{"min_confirmations": 1, "scan_interval_sec": 1}).Error; err != nil {
		t.Fatalf("configure BSC chain: %v", err)
	}
	if err := data.UpsertEvmScanCursor(mdb.NetworkBsc, 100); err != nil {
		t.Fatalf("seed cursor: %v", err)
	}
	if err := dao.Mdb.Create(&mdb.WalletAddress{
		Network: mdb.NetworkBsc,
		Address: "0xec89ef49ab259f715f3a741593f50e22a79d6555",
		Status:  mdb.TokenStatusEnable,
		Source:  mdb.WalletSourceManual,
	}).Error; err != nil {
		t.Fatalf("seed BSC wallet: %v", err)
	}

	rpcStub := new(adaptiveBackfillRPC)
	rpcServer := rpc.NewServer()
	if err := rpcServer.RegisterName("eth", rpcStub); err != nil {
		t.Fatalf("register RPC stub: %v", err)
	}
	httpServer := httptest.NewServer(rpcServer)
	defer httpServer.Close()

	client, err := ethclient.Dial(httpServer.URL)
	if err != nil {
		t.Fatalf("dial RPC stub: %v", err)
	}
	defer client.Close()
	header, err := client.HeaderByNumber(context.Background(), nil)
	if err != nil {
		t.Fatalf("load stub latest header: %v", err)
	}
	if header.Number == nil || header.Number.Int64() != 300 {
		t.Fatalf("stub latest header = %v, want 300", header.Number)
	}

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		done <- runEvmBackfillLoop(ctx, client, mdb.NetworkBsc, "[TEST]", mdb.RpcNode{}, ethereum.FilterQuery{}, func(common.Address) bool { return false })
	}()

	deadline := time.NewTimer(3 * time.Second)
	defer deadline.Stop()
	ticker := time.NewTicker(10 * time.Millisecond)
	defer ticker.Stop()
	for {
		select {
		case loopErr := <-done:
			cancel()
			t.Fatalf("backfill loop stopped before persisting cursor: %v; ranges=%v", loopErr, rpcStub.attemptedRanges())
		case <-deadline.C:
			cancel()
			t.Fatalf("cursor was not persisted after adaptive retry; ranges=%v", rpcStub.attemptedRanges())
		case <-ticker.C:
			cursor, getErr := data.GetEvmScanCursor(mdb.NetworkBsc)
			if getErr != nil {
				cancel()
				t.Fatalf("load cursor: %v", getErr)
			}
			if cursor.LastBlock == 150 {
				cancel()
				goto stopped
			}
		}
	}

stopped:
	if err := <-done; err != nil {
		t.Fatalf("backfill loop: %v", err)
	}

	ranges := rpcStub.attemptedRanges()
	if len(ranges) < 3 || ranges[0] != 200 || ranges[1] != 100 || ranges[2] != 50 {
		t.Fatalf("attempted ranges = %v, want prefix [200 100 50]", ranges)
	}
	cursor, err := data.GetEvmScanCursor(mdb.NetworkBsc)
	if err != nil {
		t.Fatalf("load final cursor: %v", err)
	}
	if cursor.LastBlock != 150 {
		t.Fatalf("cursor last_block = %d, want 150", cursor.LastBlock)
	}
}

func TestReduceEvmBackfillBatchSizeStopsAtSingleBlock(t *testing.T) {
	err := backfillRangeRPCError{code: -32005, message: "limit exceeded"}
	if got, ok := reduceEvmBackfillBatchSize(err, 200); !ok || got != 100 {
		t.Fatalf("reduce 200 = (%d, %v), want (100, true)", got, ok)
	}
	if got, ok := reduceEvmBackfillBatchSize(err, 1); ok || got != 0 {
		t.Fatalf("reduce 1 = (%d, %v), want (0, false)", got, ok)
	}
}
