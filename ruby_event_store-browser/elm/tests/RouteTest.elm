module RouteTest exposing (suite)

import Expect
import Route exposing (buildUrl, eventUrl, streamUrl)
import Test exposing (..)
import Url


withUrl : String -> (Url.Url -> Expect.Expectation) -> Expect.Expectation
withUrl url callback =
    Url.fromString url
        |> Maybe.map callback
        |> Maybe.withDefault (Expect.fail "Wrong test URL provided")


suite : Test
suite =
    describe "Route"
        [ test "handles slashes properly in stream url" <|
            \_ ->
                withUrl "https://example.org"
                    (\baseUrl ->
                        Expect.equal
                            (streamUrl baseUrl "resource/uuid")
                            "/streams/resource%2Fuuid"
                    )
        , test "handles slashes properly in event url" <|
            \_ ->
                withUrl "https://example.org"
                    (\baseUrl ->
                        Expect.equal
                            (eventUrl baseUrl "why/would-anyone-do-that")
                            "/events/why%2Fwould-anyone-do-that"
                    )
        , test "buildUrl generates proper url when subdirectory absent" <|
            \_ ->
                withUrl "https://example.org"
                    (\baseUrl ->
                        Expect.equal
                            (buildUrl baseUrl [ "something" ])
                            "/something"
                    )
        , test "buildUrl generates proper url when subdirectory absent, but with slash" <|
            \_ ->
                withUrl "https://example.org/"
                    (\baseUrl ->
                        Expect.equal
                            (buildUrl baseUrl [ "something" ])
                            "/something"
                    )
        , test "buildUrl generates proper url with subdirectory" <|
            \_ ->
                withUrl "https://example.org/res"
                    (\baseUrl ->
                        Expect.equal
                            (buildUrl baseUrl [ "something" ])
                            "/res/something"
                    )
        , test "buildUrl generates proper url with subdirectory and slash" <|
            \_ ->
                withUrl "https://example.org/res/"
                    (\baseUrl ->
                        Expect.equal
                            (buildUrl baseUrl [ "something" ])
                            "/res/something"
                    )
        , test "buildUrl generates proper url with double subdirectory" <|
            \_ ->
                withUrl "https://example.org/res/foo"
                    (\baseUrl ->
                        Expect.equal
                            (buildUrl baseUrl [ "something" ])
                            "/res/foo/something"
                    )
        ]
