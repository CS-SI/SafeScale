package consumer

import (
	"strconv"

	"github.com/CS-SI/SafeScale/v22/lib/utils/fail"
	"github.com/CS-SI/SafeScale/v22/lib/utils/valid"
	consulapi "github.com/hashicorp/consul/api"
	"github.com/sirupsen/logrus"
)

type sessionManager struct {
	client  *Client
	session *consulapi.Session
}

func (instance *sessionManager) Create(conf *settings) (*Session, fail.Error) {
	if valid.IsNull(instance) {
		return nil, fail.InvalidInstanceError()
	}

	// Defensive coding; should not happen
	if conf.ttl <= 0 {
		return nil, fail.InvalidRequestError("cannot use a ttl set to '%d'", conf.ttl)
	}

	entry := &consulapi.SessionEntry{
		Name:     conf.sessionName,
		Behavior: consulapi.SessionBehaviorDelete,
	}
	if conf.ttl > 0 {
		entry.TTL = strconv.Itoa(conf.ttl) + "s"
	}
	id, _, err := instance.session.Create(entry, nil)
	if err != nil {
		logrus.Debugf("Error while creating session: %v", err)
		return nil, fail.Wrap(err)
	}

	out := &Session{
		session:   instance.session,
		lastEntry: entry,
		name:      conf.sessionName,
		id:        id,
		ttl:       conf.ttl,
	}
	return out, nil
}

// func (instance *sessionManager) Read(id string) (*Session, fail.Error) {
// 	if valid.IsNull(instance) {
// 		return nil, fail.InvalidInstanceError()
// 	}
//
// 	entry, meta, err := instance.session.Info(id, nil)
// 	_, _ = entry, meta
// 	if err != nil {
// 		return nil, fail.Wrap(err)
// 	}
//
// 	return nil, fail.NotImplementedError()
//
// }

type Session struct {
	session     *consulapi.Session
	lastEntry   *consulapi.SessionEntry
	name        string
	id          string
	ttl         int
	stopRenewCh chan struct{}
	periodic    bool
}

func (instance *Session) IsNull() bool {
	return instance == nil || instance.session == nil || instance.lastEntry == nil || instance.id == "" || instance.name == ""
}

// Renew reset the TTL of the session (or sets a periodic renew using option WithPeriodicRenew())
func (instance *Session) Renew(opts ...Option) fail.Error {
	if valid.IsNull(instance) {
		return fail.InvalidInstanceError()
	}

	conf, xerr := newSettings(opts...)
	if xerr != nil {
		return xerr
	}

	var (
		entry *consulapi.SessionEntry
		meta  *consulapi.WriteMeta
		err   error
	)
	switch conf.periodic {
	case false:
		entry, meta, err = instance.session.Renew(instance.id, nil)
		_, _ = entry, meta
	case true:
		if conf.ttl <= 0 {
			return fail.InvalidRequestError("cannot renew the session with the ttl provided (must be strictly greater than 0)")
		}

		err = instance.session.RenewPeriodic(strconv.Itoa(conf.ttl)+"s", instance.id, nil, instance.stopRenewCh)
	}
	if err != nil {
		return fail.Wrap(err)
	}

	instance.lastEntry = entry
	instance.ttl = conf.ttl
	return fail.NotImplementedError()
}

// Delete deletes a session and stops periodic renew if set
func (instance *Session) Delete() fail.Error {
	if valid.IsNull(instance) {
		return fail.InvalidInstanceError()
	}

	if instance.periodic {
		instance.stopRenewCh <- struct{}{}
		close(instance.stopRenewCh)
	}

	meta, err := instance.session.Destroy(instance.id, nil)
	_ = meta
	if err != nil {
		return fail.Wrap(err, "failed to delete sessionManager")
	}

	*instance = Session{}
	return nil
}

// Close is a synonym of Delete
func (instance *Session) Close() fail.Error {
	return instance.Delete()
}
