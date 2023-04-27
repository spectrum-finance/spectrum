ThisBuild / version := "0.1.0-SNAPSHOT"

ThisBuild / scalaVersion := "3.2.2"

lazy val root = (project in file("."))
  .settings(
    name := "sim",
    libraryDependencies ++= Seq(
      "org.typelevel"     %% "cats-effect"     % "3.4.6",
      "co.fs2"            %% "fs2-core"        % "3.5.0",
      "org.typelevel"     %% "cats-mtl"        % "1.3.0",
      "pt.kcry"           %% "sha"             % "2.0.1",
      "org.scalatest"     %% "scalatest"       % "3.2.9",
      "org.scalatestplus" %% "scalacheck-1-15" % "3.2.9.0"
    )
  )

