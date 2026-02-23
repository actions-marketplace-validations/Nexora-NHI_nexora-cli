Output demo.gif
Set FontSize 14
Set Width 1200
Set Height 600
Set Theme "Dracula"
Set Padding 20

Type "nexora scan iac --path ./fixtures/vulnerable --format table"
Enter
Sleep 4s

Type "nexora scan k8s --path ./fixtures/vulnerable --format table"
Enter
Sleep 4s

Type "nexora scan workflows --path ./fixtures/vulnerable --format table"
Enter
Sleep 4s
