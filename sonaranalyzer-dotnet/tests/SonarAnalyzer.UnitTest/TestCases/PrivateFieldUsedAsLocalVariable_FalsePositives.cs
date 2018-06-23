using System;

namespace Tests.Diagnostics
{
    // Issue #158: https://github.com/SonarSource/sonar-csharp/issues/158
    public class Repro
    {
        bool field; // Noncompliant <-- false positive

        public void m1()
        {
            field = true;
            m2();
            Console.WriteLine(field);
        }

        public void m2()
        {
            field = false;
        }
    }
}
