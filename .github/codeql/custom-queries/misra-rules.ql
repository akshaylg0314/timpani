/**
 * SPDX-FileCopyrightText: Copyright 2026 LG Electronics Inc.
 * SPDX-License-Identifier: MIT
 *
 * @name Custom MISRA Rules for Timpani
 * @description Additional MISRA C:2012 compliance checks
 * @kind problem
 * @problem.severity warning
 * @precision medium
 * @id timpani/misra-custom
 * @tags misra-c
 *       correctness
 *       maintainability
 */

import cpp

/**
 * MISRA C:2012 Rule 8.14 - The restrict type qualifier shall not be used
 * This is a custom example query
 */
from Variable v
where v.getType().hasSpecifier("restrict")
select v, "MISRA C:2012 Rule 8.14: Use of 'restrict' qualifier is not recommended in safety-critical code."

/**
 * MISRA C:2012 Rule 21.6 - Standard library input/output functions should not be used
 * Checking for printf, scanf, etc. in production code
 */
class StandardIOFunction extends Function {
  StandardIOFunction() {
    this.hasGlobalName(["printf", "fprintf", "sprintf", "snprintf",
                        "scanf", "fscanf", "sscanf",
                        "puts", "gets", "fgets"])
  }
}

from FunctionCall fc
where fc.getTarget() instanceof StandardIOFunction
  and not fc.getFile().getBaseName().matches("%test%")
  and not fc.getFile().getBaseName().matches("%example%")
select fc, "MISRA C:2012 Advisory: Standard I/O function '" + 
          fc.getTarget().getName() + 
          "' used. Consider using safer alternatives in production code."

/**
 * MISRA C:2012 Rule 17.7 - Return value of functions should be checked
 */
from FunctionCall fc
where not exists(fc.getParent().(Expr))
  and fc.getType().getUnspecifiedType() instanceof IntType
  and not fc.getTarget().getName().matches("printf%")
select fc, "MISRA C:2012 Rule 17.7: Return value of function '" + 
          fc.getTarget().getName() + 
          "' should be checked."
