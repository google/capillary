/*
 * Copyright 2018 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package com.google.capillary.demo.android.callables;

import com.google.firebase.iid.FirebaseInstanceId;
import java.util.concurrent.Callable;

/**
 * Deletes the current FCM instance ID.
 */
public final class DelIid implements Callable<String> {

  @Override
  public String call() throws Exception {
    FirebaseInstanceId.getInstance().deleteInstanceId();
    FirebaseInstanceId.getInstance().getToken();
    return "deleted IID";
  }
}
