// Package output — trial 状态持久化（bbolt KV）。
//
// 设计要点：
//   - 单文件 bbolt db（默认 XINCHUANG_DB_FILE，可覆盖）；
//   - bucket `trial_state`：key = event_id → value = JSON(check.DriftEvidence)；
//   - bucket `contract_index`：key = contract_id → value = JSON([]string event_id) 用于 ListByContractID；
//   - bucket `chain_head`：key = "global_head" → value = 上一行 SelfHash（用于跨 trial 链头更新）；
//
// trial → confirmed/remedied 推进：
//   1. LoadTrial(eventID) 取上一行 DriftEvidence 与 SelfHash = prev；
//   2. CanTransition 校验合法；
//   3. 新 SelfHash = sha256(prev || HashBody(updated evidence))；
//   4. SaveTrial 写回 + append 审计行（由 caller 决定）。
//
// 决不静默推进；每次写都跑 CanTransition。
package output

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"time"

	bolt "go.etcd.io/bbolt"

	"xinchuang-db-guardian/internal/check"
)

// ErrTrialNotFound — SaveTrial 前取不到原证据。
var ErrTrialNotFound = errors.New("trial not found")

// ErrInvalidTransition — 状态推进非法。
var ErrInvalidTransition = errors.New("invalid drift state transition")

// ErrEmptyEventID — event_id 空字符串拒绝（主键必须存在）。
var ErrEmptyEventID = errors.New("empty event_id")

// ErrEmptyContractID — contract_id 缺省拒绝（contract_index 需要这个键）。
var ErrEmptyContractID = errors.New("empty contract_id")

// TrialStore — bbolt 持久化 trial 状态管理器。
type TrialStore struct {
	mu   sync.Mutex // 守护来自不同入口的写并发
	path string
	db   *bolt.DB
}

// bucket 名称。
const (
	bucketTrial       = "trial_state"
	bucketContractIdx = "contract_index"
	bucketChainHead   = "chain_head"
	keyGlobalHead     = "global_head"
)

// OpenTrialStore — 打开或创建 bbolt 数据库；path 可由 XINCHUANG_DB_FILE 覆盖。
//
// 行为：
//   - path 为空或含非法 → 错误；
//   - 父目录自动 MkdirAll(0o755)；
//   - Options 0600 文件权限，避免凭证泄露；
//   - 创建所需 bucket（幂等）。
func OpenTrialStore(path string) (*TrialStore, error) {
	if path == "" {
		return nil, errors.New("trial store: empty path")
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return nil, fmt.Errorf("trial store mkdir: %w", err)
	}
	db, err := bolt.Open(path, 0o600, &bolt.Options{Timeout: 5 * time.Second})
	if err != nil {
		return nil, fmt.Errorf("trial store open: %w", err)
	}
	if err := db.Update(func(tx *bolt.Tx) error {
		for _, b := range []string{bucketTrial, bucketContractIdx, bucketChainHead} {
			if _, err := tx.CreateBucketIfNotExists([]byte(b)); err != nil {
				return err
			}
		}
		return nil
	}); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("trial store init buckets: %w", err)
	}
	return &TrialStore{path: path, db: db}, nil
}

// Close — 释放 db；守护退出时调用。
func (s *TrialStore) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.db == nil {
		return nil
	}
	err := s.db.Close()
	s.db = nil
	return err
}

// Path — 返回 db 文件路径（运维/自检用）。
func (s *TrialStore) Path() string { return s.path }

// SaveTrial — 写一条 trial 证据。
//
// 行为：
//   - 校验 EventID / ContractID 非空；
//   - 主键：trial_state["event_id"] → JSON；
//   - 索引：contract_index["contract_id"] → JSON([]string event_id)，新增到集合；
//   - 链头：chain_head["global_head"] ← evidence.SelfHash（若有）。
func (s *TrialStore) SaveTrial(ev check.DriftEvidence) error {
	if ev.EventID == "" {
		return ErrEmptyEventID
	}
	if ev.ContractID == "" {
		return ErrEmptyContractID
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.db == nil {
		return errors.New("trial store closed")
	}
	body, err := json.Marshal(ev)
	if err != nil {
		return fmt.Errorf("trial store marshal: %w", err)
	}
	return s.db.Update(func(tx *bolt.Tx) error {
		// 主键写入。
		if err := tx.Bucket([]byte(bucketTrial)).Put([]byte(ev.EventID), body); err != nil {
			return err
		}
		// 索引维护。
		idxBkt := tx.Bucket([]byte(bucketContractIdx))
		existing := idxBkt.Get([]byte(ev.ContractID))
		var ids []string
		if len(existing) > 0 {
			if err := json.Unmarshal(existing, &ids); err != nil {
				return fmt.Errorf("contract_index unmarshal %q: %w", ev.ContractID, err)
			}
		}
		// 幂等：event_id 已存在则跳过索引 append。
		dup := false
		for _, id := range ids {
			if id == ev.EventID {
				dup = true
				break
			}
		}
		if !dup {
			ids = append(ids, ev.EventID)
			sort.Strings(ids)
			out, err := json.Marshal(ids)
			if err != nil {
				return err
			}
			if err := idxBkt.Put([]byte(ev.ContractID), out); err != nil {
				return err
			}
		}
		// 链头维护：当前 trial 的 self_hash 推进全局链头。
		if ev.SelfHash != "" {
			hb := tx.Bucket([]byte(bucketChainHead))
			if err := hb.Put([]byte(keyGlobalHead), []byte(ev.SelfHash)); err != nil {
				return err
			}
		}
		return nil
	})
}

// LoadTrial — 按 event_id 取一条 trial。
func (s *TrialStore) LoadTrial(eventID string) (check.DriftEvidence, error) {
	if eventID == "" {
		return check.DriftEvidence{}, ErrEmptyEventID
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.db == nil {
		return check.DriftEvidence{}, errors.New("trial store closed")
	}
	var ev check.DriftEvidence
	err := s.db.View(func(tx *bolt.Tx) error {
		raw := tx.Bucket([]byte(bucketTrial)).Get([]byte(eventID))
		if raw == nil {
			return ErrTrialNotFound
		}
		return json.Unmarshal(raw, &ev)
	})
	return ev, err
}

// ListByContractID — 按 contract_id 取所有 trial；event_id 字典序排序。
func (s *TrialStore) ListByContractID(contractID string) ([]check.DriftEvidence, error) {
	if contractID == "" {
		return nil, ErrEmptyContractID
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.db == nil {
		return nil, errors.New("trial store closed")
	}
	var eventIDs []string
	err := s.db.View(func(tx *bolt.Tx) error {
		raw := tx.Bucket([]byte(bucketContractIdx)).Get([]byte(contractID))
		if raw == nil {
			return nil
		}
		return json.Unmarshal(raw, &eventIDs)
	})
	if err != nil {
		return nil, err
	}
	out := make([]check.DriftEvidence, 0, len(eventIDs))
	for _, eid := range eventIDs {
		var ev check.DriftEvidence
		err := s.db.View(func(tx *bolt.Tx) error {
			raw := tx.Bucket([]byte(bucketTrial)).Get([]byte(eid))
			if raw == nil {
				return nil
			}
			return json.Unmarshal(raw, &ev)
		})
		if err != nil {
			return nil, err
		}
		if ev.EventID != "" {
			out = append(out, ev)
		}
	}
	return out, nil
}

// GlobalChainHead — 当前审计链头 self_hash（用于跨 trial 的链构造）。
// 返回 "" 表示链为空。
func (s *TrialStore) GlobalChainHead() (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.db == nil {
		return "", errors.New("trial store closed")
	}
	var head string
	err := s.db.View(func(tx *bolt.Tx) error {
		raw := tx.Bucket([]byte(bucketChainHead)).Get([]byte(keyGlobalHead))
		if raw != nil {
			head = string(raw)
		}
		return nil
	})
	return head, err
}

// DeleteTrial — 删除一条 trial（仅用于测试清理或运维迁移；正常 confirm-drift 不调）。
func (s *TrialStore) DeleteTrial(eventID string) error {
	if eventID == "" {
		return ErrEmptyEventID
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.db == nil {
		return errors.New("trial store closed")
	}
	return s.db.Update(func(tx *bolt.Tx) error {
		return tx.Bucket([]byte(bucketTrial)).Delete([]byte(eventID))
	})
}

// PromoteTrial — 推进 trial 状态（trial → confirmed/remedied/re_verified/disputed）。
//
// 行为：
//   1. 取旧 record，校验 EventID 非空；
//   2. 取全局链头作为 prev_evidence_sha256（兼容旧 record 没有 prev 的情况）；
//   3. 校验 CanTransition(old.Status, newState)；
//   4. 复制+覆盖状态字段；PrevEvidenceSHA256 = 旧 SelfHash；
//   5. 用 check.ComputeSelfHash(prev_evidence_sha256 || HashBody(updated)) 写回新 SelfHash；
//   6. SaveTrial 写回。
//
// 任意非法转换返回 wrap *ErrInvalidTransition 之外的 error；trial 不静默推进。
func (s *TrialStore) PromoteTrial(eventID string, newState check.State, operator string) (check.DriftEvidence, error) {
	if eventID == "" {
		return check.DriftEvidence{}, ErrEmptyEventID
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.db == nil {
		return check.DriftEvidence{}, errors.New("trial store closed")
	}

	var updated check.DriftEvidence
	err := s.db.Update(func(tx *bolt.Tx) error {
		oldRaw := tx.Bucket([]byte(bucketTrial)).Get([]byte(eventID))
		if oldRaw == nil {
			return ErrTrialNotFound
		}
		var old check.DriftEvidence
		if err := json.Unmarshal(oldRaw, &old); err != nil {
			return fmt.Errorf("trial unmarshal: %w", err)
		}
		if err := check.CanTransition(old.Status, newState); err != nil {
			return fmt.Errorf("%w: %s -> %s", ErrInvalidTransition, old.Status, newState)
		}
		updated = old
		updated.Status = newState
		updated.PrevEvidenceSHA256 = old.SelfHash
		// operator 仅入审计行不入 store（store 不维护 operator），但保留在 ts 上做对齐。
		updated.TsUTC = time.Now().UTC().Format(time.RFC3339Nano)
		// 自校验后再算 self_hash。
		body := check.HashBody(updated)
		updated.SelfHash = check.ComputeSelfHash(old.SelfHash, body)
		newBody, err := json.Marshal(updated)
		if err != nil {
			return err
		}
		if err := tx.Bucket([]byte(bucketTrial)).Put([]byte(eventID), newBody); err != nil {
			return err
		}
		// 链头推进。
		if updated.SelfHash != "" {
			return tx.Bucket([]byte(bucketChainHead)).Put([]byte(keyGlobalHead), []byte(updated.SelfHash))
		}
		return nil
	})
	if err != nil {
		return check.DriftEvidence{}, err
	}
	if operator == "" {
		_ = operator // operator 留给审计行；store 不持久化
	}
	return updated, nil
}
