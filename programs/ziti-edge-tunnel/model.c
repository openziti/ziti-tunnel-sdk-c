// Copyright 2024 NetFoundry Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#include "model/events.h"

// ******* TUNNEL EVENT BROADCAST MESSAGES
IMPL_ENUM(event_severity, EVENT_SEVERITY)
IMPL_MODEL(status_event, STATUS_EVENT)
IMPL_MODEL(action_event, ACTION_EVENT)
IMPL_MODEL(identity_event, IDENTITY_EVENT)
IMPL_MODEL(services_event, SERVICES_EVENT)
IMPL_MODEL(tunnel_status_event, TUNNEL_STATUS_EVENT)
IMPL_MODEL(mfa_status_event, MFA_STATUS_EVENT)
IMPL_MODEL(tunnel_metrics_event, TUNNEL_METRICS_EVENT)
IMPL_MODEL(notification_message, TUNNEL_NOTIFICATION_MESSAGE)
IMPL_MODEL(notification_event, TUNNEL_NOTIFICATION_EVENT)
