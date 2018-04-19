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

package com.google.capillary.android;

import android.os.Build.VERSION;
import java.lang.reflect.Field;
import java.lang.reflect.Modifier;

final class TestUtils {

  static void setBuildVersion(int version) throws Exception {
    Field field = VERSION.class.getDeclaredField("SDK_INT");

    Field modifiersField = Field.class.getDeclaredField("modifiers");
    boolean isModifierAccessible = modifiersField.isAccessible();
    modifiersField.setAccessible(true);
    modifiersField.setInt(field, field.getModifiers() & ~Modifier.FINAL);
    modifiersField.setAccessible(isModifierAccessible);

    boolean isAccessible = field.isAccessible();
    field.setAccessible(true);
    field.set(null, version);
    field.setAccessible(isAccessible);
  }

}
